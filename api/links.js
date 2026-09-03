import { requireAdmin } from "./auth.js";
import { put, list, get, del } from "@vercel/blob";

const PREFIX = "repayment-events/";

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"
    }
  });
}

function eventPath(id, type) {
  const safeId = String(id).replace(/[^a-zA-Z0-9_-]/g, "");
  const nonce = Math.random().toString(36).slice(2, 10);
  return `${PREFIX}${safeId}/${Date.now()}-${nonce}-${type}.json`;
}

async function writeEvent(event) {
  await put(eventPath(event.id, event.type), JSON.stringify(event), {
    access: "private",
    addRandomSuffix: false,
    allowOverwrite: false,
    contentType: "application/json",
    cacheControlMaxAge: 60
  });
}

async function readEvent(blob) {
  const result = await get(blob.url, { access: "private" });
  if (!result || result.statusCode !== 200 || !result.stream) return null;
  const text = await new Response(result.stream).text();
  try { return JSON.parse(text); } catch (_) { return null; }
}

async function allEvents() {
  let cursor;
  const blobs = [];
  do {
    const result = await list({ prefix: PREFIX, limit: 1000, cursor });
    blobs.push(...result.blobs);
    cursor = result.hasMore ? result.cursor : undefined;
  } while (cursor);

  const events = await Promise.all(blobs.map(readEvent));
  return events.filter(Boolean).sort((a, b) => String(a.time || "").localeCompare(String(b.time || "")));
}

function aggregate(events) {
  const map = new Map();
  for (const event of events) {
    if (!event.id) continue;
    if (event.type === "create") {
      map.set(event.id, { ...event.item });
    } else if (event.type === "update") {
      const current = map.get(event.id);
      if (current) Object.assign(current, event.patch || {});
    }
  }
  return [...map.values()].sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
}

export async function GET(request) {
  try {
    if (!requireAdmin(request)) return json({ error: "Unauthorized" }, 401);
    const events = await allEvents();
    const links = aggregate(events);
    const id = new URL(request.url).searchParams.get("id");
    if (id) {
      const item = links.find(x => x.id === id);
      return item ? json({ link: item }) : json({ error: "Link not found" }, 404);
    }
    return json({ links });
  } catch (error) {
    console.error(error);
    return json({ error: "Storage is not configured. Connect a Vercel Blob store to this project." }, 500);
  }
}

export async function POST(request) {
  try {
    const body = await request.json();
    const action = body.action;

    if (action === "create") {
      if (!requireAdmin(request)) return json({ error: "Unauthorized" }, 401);
      if (!body.item?.id) return json({ error: "Missing link data" }, 400);
      await writeEvent({
        id: body.item.id,
        type: "create",
        time: new Date().toISOString(),
        item: body.item
      });
      return json({ ok: true, link: body.item });
    }

    if (action === "update") {
      if (!body.id || !body.patch || typeof body.patch !== "object") {
        return json({ error: "Missing update data" }, 400);
      }
      await writeEvent({
        id: body.id,
        type: "update",
        time: new Date().toISOString(),
        patch: body.patch
      });
      return json({ ok: true });
    }

    if (action === "clear") {
      if (!requireAdmin(request)) return json({ error: "Unauthorized" }, 401);
      let cursor;
      const urls = [];
      do {
        const result = await list({ prefix: PREFIX, limit: 1000, cursor });
        urls.push(...result.blobs.map(b => b.url));
        cursor = result.hasMore ? result.cursor : undefined;
      } while (cursor);
      if (urls.length) await del(urls);
      return json({ ok: true, deleted: urls.length });
    }

    return json({ error: "Unknown action" }, 400);
  } catch (error) {
    console.error(error);
    return json({ error: error?.message || "Server error" }, 500);
  }
}
