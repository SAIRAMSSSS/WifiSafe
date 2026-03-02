import { ReactNode } from "react";
import { Header } from "./Header";

interface LayoutProps {
  children: ReactNode;
}

export const Layout = ({ children }: LayoutProps) => {
  return (
    <div className="min-h-screen bg-background cyber-grid">
      <Header />
      <main className="pt-20 pb-8 px-4">
        <div className="container mx-auto">
          {children}
        </div>
      </main>
    </div>
  );
};
