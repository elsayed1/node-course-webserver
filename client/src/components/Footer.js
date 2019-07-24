import React from "react";

export default function Footer() {
  return (
    <div
      style={{
        padding: "15px 0"
      }}
      className="bg-dark text-white text-center footer"
    >
      copyright &copy; {new Date().getFullYear()} Sayed Alaa
    </div>
  );
}
