import Providers from "@/components/providers";
import "./globals.css";

export const metadata = {
  title: "VAPT Security Platform",
  description: "Security vulnerability assessment platform",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en" className="h-full">
      <body className="min-h-full overflow-x-hidden bg-canvas text-text antialiased">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}