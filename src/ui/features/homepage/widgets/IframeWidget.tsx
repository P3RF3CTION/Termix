import { Globe } from "lucide-react";
import { registerWidget } from "./WidgetRegistry";
import type {
  IframeConfig,
  WidgetComponentProps,
} from "@/types/homepage-types";
import { GRID_SIZE } from "@/types/homepage-types";
import { WidgetTitle } from "./WidgetTitle";
import { safeUrl } from "@/lib/safe-url";

function IframeWidget({
  widget,
  config,
  isReadOnly,
}: WidgetComponentProps<IframeConfig>) {
  const { url, scrolling } = config;
  // `javascript:`, `data:`, and `file:` URLs in a same-origin sandbox let the
  // frame script run in Termix's origin -- localStorage.jwt exfiltration
  // becomes a one-click attack. Only http(s) URLs are ever framed.
  const src = safeUrl(url);

  if (!url) {
    return (
      <div className="flex flex-col items-center justify-center w-full h-full gap-2 text-muted-foreground/50">
        <Globe size={24} />
        <span className="text-xs">Configure a URL in widget settings</span>
      </div>
    );
  }

  if (!src) {
    return (
      <div className="flex flex-col items-center justify-center w-full h-full gap-2 text-destructive/70 p-3 text-center">
        <Globe size={24} />
        <span className="text-xs">
          URL scheme not allowed. Use http:// or https://.
        </span>
      </div>
    );
  }

  return (
    <div className="flex flex-col w-full h-full overflow-hidden">
      <WidgetTitle title={widget.title} icon={<Globe size={11} />} />
      <div className="relative flex-1">
        <iframe
          src={src}
          // Deliberately no `allow-same-origin`: an untrusted URL that also
          // gets same-origin access is exactly the combination the HTML spec
          // calls out as unsafe. Losing it costs the framed page its cookies
          // for its own origin -- a fair trade for not handing it ours.
          sandbox="allow-scripts allow-forms allow-popups allow-popups-to-escape-sandbox"
          referrerPolicy="no-referrer"
          scrolling={scrolling ? "yes" : "no"}
          className="w-full h-full border-0"
          title="Embedded content"
        />
        {/* Block interaction in read-only mode so the canvas can still pan */}
        {isReadOnly && <div className="absolute inset-0 pointer-events-none" />}
      </div>
    </div>
  );
}

registerWidget<IframeConfig>({
  id: "iframe_embed",
  name: "iFrame Embed",
  description: "Embed any URL in an iframe",
  category: "info",
  icon: <Globe size={14} />,
  defaultConfig: { url: "", scrolling: true },
  defaultSize: { w: GRID_SIZE * 14, h: GRID_SIZE * 12 },
  minSize: { w: GRID_SIZE * 2, h: GRID_SIZE * 2 },
  component: IframeWidget,
});

export { IframeWidget };
