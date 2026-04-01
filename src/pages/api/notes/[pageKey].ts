export const prerender = false;

import type { APIRoute } from 'astro';
import { isValidKey, getNote, saveNote, deleteNote } from '../../../lib/notes';

export const GET: APIRoute = ({ params }) => {
  const { pageKey } = params;
  if (!pageKey || !isValidKey(pageKey)) {
    return new Response('Invalid page key', { status: 400 });
  }
  return new Response(getNote(pageKey), {
    status: 200,
    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
  });
};

export const PUT: APIRoute = async ({ params, request }) => {
  const { pageKey } = params;
  if (!pageKey || !isValidKey(pageKey)) {
    return new Response('Invalid page key', { status: 400 });
  }
  const content = await request.text();
  saveNote(pageKey, content);
  return new Response(null, { status: 204 });
};

export const DELETE: APIRoute = ({ params }) => {
  const { pageKey } = params;
  if (!pageKey || !isValidKey(pageKey)) {
    return new Response('Invalid page key', { status: 400 });
  }
  deleteNote(pageKey);
  return new Response(null, { status: 204 });
};
