import satori from 'satori';
import { Resvg } from '@resvg/resvg-js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(__dirname, '..');

const fontData = fs.readFileSync(
  path.join(root, 'node_modules/@fontsource/inter/files/inter-latin-700-normal.woff')
).buffer;

const fontDataReg = fs.readFileSync(
  path.join(root, 'node_modules/@fontsource/inter/files/inter-latin-400-normal.woff')
).buffer;

async function generate({ filename, leftLabel, leftSub, leftColor, rightLabel, rightSub, rightColor, tagline }) {
  const svg = await satori(
    {
      type: 'div',
      props: {
        style: {
          width: '1200px',
          height: '630px',
          display: 'flex',
          flexDirection: 'column',
          background: '#080c18',
          position: 'relative',
          fontFamily: 'Inter',
          overflow: 'hidden',
        },
        children: [
          // Top accent bar
          {
            type: 'div',
            props: {
              style: {
                position: 'absolute',
                top: '0', left: '0',
                width: '1200px', height: '4px',
                background: 'linear-gradient(90deg, #38bdf8 0%, #818cf8 100%)',
              },
              children: '',
            },
          },
          // Left glow
          {
            type: 'div',
            props: {
              style: {
                position: 'absolute',
                top: '-80px', left: '-80px',
                width: '480px', height: '480px',
                background: `radial-gradient(circle, ${leftColor}22 0%, transparent 70%)`,
              },
              children: '',
            },
          },
          // Right glow
          {
            type: 'div',
            props: {
              style: {
                position: 'absolute',
                bottom: '-80px', right: '-80px',
                width: '480px', height: '480px',
                background: `radial-gradient(circle, ${rightColor}22 0%, transparent 70%)`,
              },
              children: '',
            },
          },
          // Main content row
          {
            type: 'div',
            props: {
              style: {
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flex: '1',
                gap: '0px',
                padding: '60px 80px 20px',
              },
              children: [
                // Left card
                {
                  type: 'div',
                  props: {
                    style: {
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: 'center',
                      justifyContent: 'center',
                      flex: '1',
                      background: `${leftColor}12`,
                      border: `1px solid ${leftColor}33`,
                      borderRadius: '16px',
                      padding: '40px 32px',
                      gap: '12px',
                    },
                    children: [
                      {
                        type: 'div',
                        props: {
                          style: { fontSize: '48px', fontWeight: 700, color: leftColor, letterSpacing: '-0.02em' },
                          children: leftLabel,
                        },
                      },
                      {
                        type: 'div',
                        props: {
                          style: { fontSize: '18px', color: '#94a3b8', textAlign: 'center' },
                          children: leftSub,
                        },
                      },
                    ],
                  },
                },
                // VS badge
                {
                  type: 'div',
                  props: {
                    style: {
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      width: '72px',
                      height: '72px',
                      borderRadius: '50%',
                      background: '#0f1526',
                      border: '1px solid #1e2a45',
                      fontSize: '18px',
                      fontWeight: 700,
                      color: '#64748b',
                      flexShrink: '0',
                      margin: '0 20px',
                    },
                    children: 'vs',
                  },
                },
                // Right card
                {
                  type: 'div',
                  props: {
                    style: {
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: 'center',
                      justifyContent: 'center',
                      flex: '1',
                      background: `${rightColor}12`,
                      border: `1px solid ${rightColor}33`,
                      borderRadius: '16px',
                      padding: '40px 32px',
                      gap: '12px',
                    },
                    children: [
                      {
                        type: 'div',
                        props: {
                          style: { fontSize: '48px', fontWeight: 700, color: rightColor, letterSpacing: '-0.02em' },
                          children: rightLabel,
                        },
                      },
                      {
                        type: 'div',
                        props: {
                          style: { fontSize: '18px', color: '#94a3b8', textAlign: 'center' },
                          children: rightSub,
                        },
                      },
                    ],
                  },
                },
              ],
            },
          },
          // Bottom bar
          {
            type: 'div',
            props: {
              style: {
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '0 80px 40px',
              },
              children: [
                {
                  type: 'div',
                  props: {
                    style: { fontSize: '20px', color: '#64748b' },
                    children: tagline,
                  },
                },
                {
                  type: 'div',
                  props: {
                    style: { fontSize: '20px', fontWeight: 700, color: '#38bdf8' },
                    children: 'AuthLayer',
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
      fonts: [
        { name: 'Inter', data: fontData, weight: 700, style: 'normal' },
        { name: 'Inter', data: fontDataReg, weight: 400, style: 'normal' },
      ],
    }
  );

  const png = new Resvg(svg).render().asPng();
  const out = path.join(root, 'public/images/og', filename);
  fs.writeFileSync(out, png);
  console.log(`Generated: ${out}`);
}

await generate({
  filename: 'cognito-vs-auth0.png',
  leftLabel: 'Cognito',
  leftSub: 'AWS Identity Platform',
  leftColor: '#f59e0b',
  rightLabel: 'Auth0',
  rightSub: 'Okta Identity Cloud',
  rightColor: '#38bdf8',
  tagline: 'Identity Provider Comparison',
});

await generate({
  filename: 'cognito-vs-okta.png',
  leftLabel: 'Cognito',
  leftSub: 'AWS Identity Platform',
  leftColor: '#f59e0b',
  rightLabel: 'Okta',
  rightSub: 'Enterprise Identity Leader',
  rightColor: '#818cf8',
  tagline: 'Identity Provider Comparison',
});

console.log('Done.');
