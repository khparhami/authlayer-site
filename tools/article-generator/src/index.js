const GITHUB_REPO = 'khparhami/authlayer-site';
const GITHUB_BRANCH = 'main';

const RSS_FEEDS = [
  'https://krebsonsecurity.com/feed/',
  'https://feeds.feedburner.com/TheHackersNews',
  'https://www.bleepingcomputer.com/feed/',
  'https://auth0.com/blog/rss.xml',
];

// Tags we care about — skip unrelated stories
const RELEVANT_KEYWORDS = [
  'auth', 'oauth', 'jwt', 'token', 'password', 'passkey', 'mfa', '2fa',
  'identity', 'zero trust', 'phishing', 'credential', 'api security',
  'breach', 'vulnerability', 'exploit', 'cve', 'ransomware', 'encryption',
  'certificate', 'ssl', 'tls', 'saml', 'oidc', 'sso', 'okta', 'active directory',
];

function extractTag(text) {
  const t = text.toLowerCase();
  if (t.includes('oauth') || t.includes('oidc') || t.includes('sso') || t.includes('saml')) return 'oauth';
  if (t.includes('jwt') || t.includes('token')) return 'jwt';
  if (t.includes('mfa') || t.includes('2fa') || t.includes('authenticator')) return 'mfa';
  if (t.includes('passkey') || t.includes('fido') || t.includes('webauthn')) return 'passkeys';
  if (t.includes('phishing') || t.includes('credential') || t.includes('breach')) return 'threats';
  if (t.includes('api') || t.includes('endpoint')) return 'api-security';
  if (t.includes('zero trust') || t.includes('zero-trust')) return 'zero-trust';
  return 'security';
}

function slugify(title) {
  return title
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .slice(0, 60)
    .replace(/-$/, '');
}

function parseRssItems(xml) {
  const items = [];
  const itemRegex = /<item>([\s\S]*?)<\/item>/g;
  let match;
  while ((match = itemRegex.exec(xml)) !== null) {
    const block = match[1];
    const get = (tag) => {
      const m = block.match(new RegExp(`<${tag}[^>]*>(?:<!\\[CDATA\\[)?([\\s\\S]*?)(?:\\]\\]>)?<\\/${tag}>`, 'i'));
      return m ? m[1].trim() : '';
    };
    items.push({
      title: get('title'),
      link: get('link'),
      description: get('description').replace(/<[^>]+>/g, '').slice(0, 600),
      pubDate: get('pubDate'),
    });
  }
  return items;
}

function isRelevant(item) {
  const text = `${item.title} ${item.description}`.toLowerCase();
  return RELEVANT_KEYWORDS.some(kw => text.includes(kw));
}

async function fetchFeed(url) {
  try {
    const res = await fetch(url, { headers: { 'User-Agent': 'AuthLayer-Bot/1.0' }, signal: AbortSignal.timeout(8000) });
    if (!res.ok) return [];
    const xml = await res.text();
    return parseRssItems(xml);
  } catch {
    return [];
  }
}

async function generateArticle(ai, story) {
  const systemPrompt = `You are a senior security engineer with 12 years of experience breaking and building authentication systems. You write for AuthLayer.dev — a technical blog for developers who want straight talk about auth and security.

Your voice:
- First-person, opinionated. You have a take, you state it.
- Short sentences mixed with longer technical ones. Not uniform.
- You use contractions: don't, can't, it's, you're.
- You reference real tools, CVEs, RFCs, version numbers. Specificity signals expertise.
- You ask rhetorical questions and answer them bluntly.
- You're occasionally dry/wry. Not trying to be funny, just not corporate.
- You write from experience: "I've seen this in prod", "every pentest I've done in the last year".
- No "Introduction" or "Conclusion" headers. No "In summary". No "It's worth noting".
- Not every section is the same length. Some ideas get two sentences, some get six paragraphs.
- You never use the words: "delve", "crucial", "landscape", "robust", "leverage", "utilize", "comprehensive", "ensure", "streamline", "game-changer".

Output format: valid markdown with YAML frontmatter. Article body should be 600-900 words.

Frontmatter format:
---
title: "Title here"
description: "One sentence, under 160 chars, no quotes inside"
pubDate: DATEHERE
author: "AuthLayer Team"
tags: [TAGSHERE]
featured: false
---`;

  const userPrompt = `Write an original article inspired by this security story. Don't summarise it — use it as a jumping-off point for your own analysis, opinion, or deeper technical explanation.

Story title: ${story.title}
Story summary: ${story.description}
Original source: ${story.link}

Today's date: ${new Date().toISOString().split('T')[0]}
Use this as the pubDate in frontmatter.

Pick 2-3 tags from: oauth, jwt, mfa, passkeys, zero-trust, api-security, security, threats, vulnerabilities, guide

Write the full article now.`;

  const response = await ai.run('@cf/meta/llama-3.3-70b-instruct-fp8-fast', {
    messages: [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userPrompt },
    ],
    max_tokens: 2048,
  });

  return response.response;
}

async function commitToGitHub(token, slug, content) {
  const path = `src/content/blog/${slug}.md`;
  const url = `https://api.github.com/repos/${GITHUB_REPO}/contents/${path}`;

  // Check if file already exists (get SHA if so)
  let sha;
  const check = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      'User-Agent': 'AuthLayer-Bot/1.0',
    },
  });
  if (check.ok) {
    const existing = await check.json();
    sha = existing.sha;
  }

  const body = {
    message: `content: add article "${slug}"`,
    content: btoa(unescape(encodeURIComponent(content))),
    branch: GITHUB_BRANCH,
    ...(sha ? { sha } : {}),
  };

  const res = await fetch(url, {
    method: 'PUT',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      'User-Agent': 'AuthLayer-Bot/1.0',
    },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`GitHub API error ${res.status}: ${err}`);
  }

  return await res.json();
}

export default {
  async fetch(request, env) {
    // Simple auth check — pass ?key=YOUR_SECRET in the URL
    const url = new URL(request.url);
    const key = url.searchParams.get('key');
    if (env.TRIGGER_KEY && key !== env.TRIGGER_KEY) {
      return new Response('Unauthorized', { status: 401 });
    }

    try {
      // 1. Fetch all feeds in parallel
      const allItems = (await Promise.all(RSS_FEEDS.map(fetchFeed))).flat();

      // 2. Filter to relevant stories only
      const relevant = allItems.filter(isRelevant);
      if (relevant.length === 0) {
        return new Response(JSON.stringify({ error: 'No relevant stories found' }), {
          status: 404, headers: { 'Content-Type': 'application/json' },
        });
      }

      // 3. Pick the first relevant story
      const story = relevant[0];

      // 4. Generate article
      const markdown = await generateArticle(env.AI, story);

      // 5. Extract title from frontmatter for slug
      const titleMatch = markdown.match(/^title:\s*["']?(.+?)["']?\s*$/m);
      const title = titleMatch ? titleMatch[1] : story.title;
      const slug = slugify(title);
      const tag = extractTag(`${story.title} ${story.description}`);

      // 6. Commit to GitHub
      await commitToGitHub(env.GITHUB_TOKEN, slug, markdown);

      return new Response(JSON.stringify({
        success: true,
        slug,
        title,
        tag,
        source: story.link,
      }), {
        headers: { 'Content-Type': 'application/json' },
      });

    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), {
        status: 500, headers: { 'Content-Type': 'application/json' },
      });
    }
  },
};
