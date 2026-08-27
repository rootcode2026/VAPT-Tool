import "./globals.css";

export const metadata = {
  title: "VAPT Security Platform",
  description: "Security vulnerability assessment platform",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en" className="h-full">
      <body className="min-h-full bg-slate-950 text-white antialiased">
        {children}
      </body>
    </html>
  );
}