export const prerender = true;

import type { APIContext } from 'astro';
import { getCollection } from 'astro:content';
import satori from 'satori';
import { Resvg } from '@resvg/resvg-js';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

export async function getStaticPaths() {
  const posts = await getCollection('blog');
  return posts.map(post => ({
    params: { slug: post.slug },
    props: {
      title: post.data.title,
      description: post.data.description,
      tags: post.data.tags,
      image: post.data.image,
    },
  }));
}

export async function GET({ props }: APIContext) {
  const { title, description, tags, image: articleImage } = props as {
    title: string;
    description: string;
    tags: string[];
    image?: string;
  };

  const fontPath = path.join(
    process.cwd(),
    'node_modules/@fontsource/inter/files/inter-latin-700-normal.woff'
  );
  const fontData = fs.readFileSync(fontPath).buffer;

  const truncatedDesc =
    description.length > 130 ? description.slice(0, 130) + '…' : description;

  // Load background image if the article has one (local path under /public)
  let bgDataUrl: string | null = null;
  if (articleImage && articleImage.startsWith('/')) {
    try {
      const imgPath = path.join(process.cwd(), 'public', articleImage);
      const imgBuf = fs.readFileSync(imgPath);
      bgDataUrl = `data:image/jpeg;base64,${imgBuf.toString('base64')}`;
    } catch (_) {
      // fall through to plain dark background
    }
  }

  const hasPhoto = bgDataUrl !== null;

  const layers: object[] = [];

  // Photo layer
  if (hasPhoto) {
    layers.push({
      type: 'div',
      props: {
        style: {
          position: 'absolute',
          top: '0',
          left: '0',
          width: '1200px',
          height: '630px',
          backgroundImage: `url(${bgDataUrl})`,
          backgroundSize: 'cover',
          backgroundPosition: 'center',
        },
        children: '',
      },
    });
    // Dark gradient so text is readable
    layers.push({
      type: 'div',
      props: {
        style: {
          position: 'absolute',
          top: '0',
          left: '0',
          width: '1200px',
          height: '630px',
          background:
            'linear-gradient(to bottom, rgba(8,12,24,0.35) 0%, rgba(8,12,24,0.72) 45%, rgba(8,12,24,0.97) 100%)',
        },
        children: '',
      },
    });
  }

  // Top accent bar
  layers.push({
    type: 'div',
    props: {
      style: {
        position: 'absolute',
        top: '0',
        left: '0',
        width: '1200px',
        height: '4px',
        background: 'linear-gradient(90deg, #38bdf8 0%, #818cf8 100%)',
      },
      children: '',
    },
  });

  // Content block pinned to bottom
  layers.push({
    type: 'div',
    props: {
      style: {
        position: 'absolute',
        bottom: '0',
        left: '0',
        width: '1200px',
        display: 'flex',
        flexDirection: 'column',
        padding: '64px',
      },
      children: [
        // Tags
        {
          type: 'div',
          props: {
            style: { display: 'flex', gap: '8px', marginBottom: '24px' },
            children: tags.slice(0, 3).map(tag => ({
              type: 'span',
              props: {
                style: {
                  fontSize: '13px',
                  color: '#38bdf8',
                  background: 'rgba(56,189,248,0.15)',
                  border: '1px solid rgba(56,189,248,0.3)',
                  padding: '4px 14px',
                  borderRadius: '9999px',
                  textTransform: 'uppercase',
                  letterSpacing: '0.06em',
                  fontWeight: 700,
                },
                children: tag,
              },
            })),
          },
        },
        // Title
        {
          type: 'div',
          props: {
            style: {
              fontSize: title.length > 60 ? '38px' : '50px',
              fontWeight: 700,
              color: '#ffffff',
              lineHeight: 1.2,
              marginBottom: '16px',
              maxWidth: '1050px',
            },
            children: title,
          },
        },
        // Description
        {
          type: 'div',
          props: {
            style: {
              fontSize: '20px',
              color: hasPhoto ? '#e2e8f0' : '#94a3b8',
              lineHeight: 1.5,
              marginBottom: '36px',
              maxWidth: '980px',
            },
            children: truncatedDesc,
          },
        },
        // Footer
        {
          type: 'div',
          props: {
            style: {
              display: 'flex',
              alignItems: 'center',
              gap: '12px',
              borderTop: `1px solid ${hasPhoto ? 'rgba(255,255,255,0.15)' : '#1e2a45'}`,
              paddingTop: '20px',
            },
            children: [
              {
                type: 'span',
                props: {
                  style: { fontSize: '20px', color: '#38bdf8', fontWeight: 700 },
                  children: 'AuthLayer',
                },
              },
              {
                type: 'span',
                props: {
                  style: { color: hasPhoto ? 'rgba(255,255,255,0.2)' : '#1e2a45', fontSize: '20px' },
                  children: '·',
                },
              },
              {
                type: 'span',
                props: {
                  style: { fontSize: '18px', color: hasPhoto ? '#94a3b8' : '#64748b' },
                  children: 'authlayer.dev',
                },
              },
            ],
          },
        },
      ],
    },
  });

  const svg = await satori(
    {
      type: 'div',
      props: {
        style: {
          width: '1200px',
          height: '630px',
          display: 'flex',
          position: 'relative',
          fontFamily: 'Inter',
          background: '#080c18',
        },
        children: layers,
      },
    },
    {
      width: 1200,
      height: 630,
      fonts: [{ name: 'Inter', data: fontData, weight: 700, style: 'normal' }],
    }
  );

  const png = new Resvg(svg).render().asPng();

  return new Response(png, {
    headers: {
      'Content-Type': 'image/png',
      'Cache-Control': 'public, max-age=31536000, immutable',
    },
  });
}
