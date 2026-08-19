import { useEffect, useRef, useState } from 'react';

import { WS_BASE_URL } from '@/service/api.service';
import { getToken } from '@/service/auth.service';

export type WsState = 'connecting' | 'open' | 'closed';

interface Options<T> {
  /** Canal : "packets" | "stats" | "alerts" */
  channel: string;
  onMessage: (payload: T) => void;
  enabled?: boolean;
}

/**
 * Abonnement a un canal WebSocket du backend, avec reconnexion exponentielle
 * plafonnee a 15 s et ping applicatif toutes les 25 s pour tenir la connexion.
 */
export function useWebSocket<T = unknown>({ channel, onMessage, enabled = true }: Options<T>) {
  const [state, setState] = useState<WsState>('closed');

  // Le handler est garde dans une ref pour que sa recreation ne relance pas la connexion
  const handlerRef = useRef(onMessage);
  useEffect(() => {
    handlerRef.current = onMessage;
  }, [onMessage]);

  useEffect(() => {
    if (!enabled) return;

    let socket: WebSocket | null = null;
    let reconnectTimer: number | undefined;
    let pingTimer: number | undefined;
    let attempt = 0;
    let disposed = false;

    const connect = () => {
      const token = getToken();
      if (!token || disposed) return;

      setState('connecting');
      socket = new WebSocket(`${WS_BASE_URL}/${channel}?token=${encodeURIComponent(token)}`);

      socket.onopen = () => {
        attempt = 0;
        setState('open');
        pingTimer = window.setInterval(() => socket?.send('ping'), 25000);
      };

      socket.onmessage = (event) => {
        try {
          handlerRef.current(JSON.parse(event.data) as T);
        } catch {
          // Message non-JSON : ignore
        }
      };

      socket.onclose = () => {
        setState('closed');
        window.clearInterval(pingTimer);
        if (disposed) return;
        attempt += 1;
        reconnectTimer = window.setTimeout(connect, Math.min(1000 * 2 ** attempt, 15000));
      };

      socket.onerror = () => socket?.close();
    };

    connect();

    return () => {
      disposed = true;
      window.clearTimeout(reconnectTimer);
      window.clearInterval(pingTimer);
      socket?.close();
    };
  }, [channel, enabled]);

  return state;
}
