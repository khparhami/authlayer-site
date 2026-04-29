import { getCollection } from 'astro:content';

export async function GET() {
  const posts = await getCollection('blog');
  const site = 'https://authlayer.dev';

  const staticPages = ['/', '/blog', '/about'];
  const postPages = posts.map(p => `/blog/${p.slug}`);
  const allPages = [...staticPages, ...postPages];

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${allPages.map(path => `  <url>
    <loc>${site}${path}</loc>
    <changefreq>${path === '/' ? 'daily' : 'weekly'}</changefreq>
    <priority>${path === '/' ? '1.0' : path.startsWith('/blog/') ? '0.8' : '0.6'}</priority>
  </url>`).join('\n')}
</urlset>`;

  return new Response(xml, {
    headers: {
      'Content-Type': 'application/xml',
      'Cache-Control': 'public, max-age=3600',
    },
  });
}
