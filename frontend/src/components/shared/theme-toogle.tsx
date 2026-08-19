import { Moon, Sun } from "lucide-react";
import { useTheme } from "./theme-provider";

import { Button } from "@/components/ui/button";


/** Bouton de bascule entre le theme clair et le theme sombre. */
export function ModeToggle() {
  const { theme, setTheme } = useTheme();

  const toggleTheme = () => {
    setTheme(theme === 'light' ? 'dark' : 'light');
  };

    return (
        <Button
            variant="ghost"
            size="icon"
            onClick={toggleTheme}
            className="h-9 w-9"
            title={theme === 'light' ? 'Mode sombre' : 'Mode clair'}
            >
            {theme === 'light' ? (
                <Moon className="size-4" />
            ) : (
                <Sun className="size-4" />
            )}
            <span className="sr-only">Basculer le thème</span>
        </Button>
    );
}