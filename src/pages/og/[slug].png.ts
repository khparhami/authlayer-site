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
    },
  }));
}

export async function GET({ props }: APIContext) {
  const { title, description, tags } = props as {
    title: string;
    description: string;
    tags: string[];
  };

  const fontPath = path.join(
    path.dirname(fileURLToPath(import.meta.url)),
    '../../../node_modules/@fontsource/inter/files/inter-latin-700-normal.woff'
  );
  const fontData = fs.readFileSync(fontPath).buffer;

  const truncatedDesc =
    description.length > 130 ? description.slice(0, 130) + '…' : description;

  const svg = await satori(
    {
      type: 'div',
      props: {
        style: {
          width: '1200px',
          height: '630px',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'flex-end',
          padding: '64px',
          background: '#080c18',
          fontFamily: 'Inter',
          position: 'relative',
        },
        children: [
          // Top accent bar
          {
            type: 'div',
            props: {
              style: {
                position: 'absolute',
                top: '0',
                left: '0',
                width: '100%',
                height: '4px',
                background: 'linear-gradient(90deg, #38bdf8 0%, #818cf8 100%)',
              },
              children: '',
            },
          },
          // Tags
          {
            type: 'div',
            props: {
              style: { display: 'flex', gap: '8px', marginBottom: '28px' },
              children: tags.slice(0, 3).map(tag => ({
                type: 'span',
                props: {
                  style: {
                    fontSize: '14px',
                    color: '#38bdf8',
                    background: 'rgba(56,189,248,0.12)',
                    border: '1px solid rgba(56,189,248,0.25)',
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
                fontSize: title.length > 60 ? '40px' : '52px',
                fontWeight: 700,
                color: '#ffffff',
                lineHeight: 1.2,
                marginBottom: '20px',
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
                fontSize: '22px',
                color: '#94a3b8',
                lineHeight: 1.5,
                marginBottom: '48px',
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
                borderTop: '1px solid #1e2a45',
                paddingTop: '24px',
              },
              children: [
                {
                  type: 'span',
                  props: {
                    style: { fontSize: '22px', color: '#38bdf8', fontWeight: 700 },
                    children: 'AuthLayer',
                  },
                },
                {
                  type: 'span',
                  props: {
                    style: { color: '#1e2a45', fontSize: '22px' },
                    children: '·',
                  },
                },
                {
                  type: 'span',
                  props: {
                    style: { fontSize: '20px', color: '#64748b' },
                    children: 'authlayer.dev',
                  },
                },
              ],
            },
          },
        ],
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
