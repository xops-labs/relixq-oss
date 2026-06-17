import { redirect } from 'next/navigation';

// Marketing lives on the separate website project; the self-hosted app's
// front door is the About page.
export default function Home() {
  redirect('/about');
}
