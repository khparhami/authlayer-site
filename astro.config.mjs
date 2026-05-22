import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';

export default defineConfig({
  site: 'https://authlayer.dev',
  output: 'hybrid',
  adapter: cloudflare({ mode: 'directory' }),
  vite: {
    // @resvg/resvg-js and satori are only used in prerendered OG image pages.
    // They must not be bundled into the Cloudflare Worker.
    ssr: {
      external: ['@resvg/resvg-js', 'satori'],
    },
    build: {
      rollupOptions: {
        external: [/^node:/, 'fs', 'path', 'url', 'buffer', '@resvg/resvg-js', 'satori'],
      },
    },
  },
});
