import type { Metadata } from 'next';
import Link from 'next/link';
import { signOut } from '../lib/actions';
import './globals.css';

export const metadata: Metadata = {
  title: 'VERA — review queue',
  description: 'Decide whether an agent action should happen.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <header className="top">
          <div className="inner">
            <Link href="/" className="brand">
              VERA
            </Link>
            <span className="brand-sub">review queue</span>
            <span className="spacer" />
            <form action={signOut}>
              <button type="submit" className="quiet" style={{ padding: '5px 10px', fontSize: 13 }}>
                Sign out
              </button>
            </form>
          </div>
        </header>
        {children}
      </body>
    </html>
  );
}
