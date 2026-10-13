import React from 'react'

/**
 * Visually-hidden live region: announces new blocks to screen reader users
 * as they happen, without needing to watch the table. This is the kind of
 * thing a "vanilla JS polling" dashboard almost always skips -- a sighted
 * user sees the new red row appear, but a screen reader user gets nothing
 * unless this region exists.
 */
export default function AlertAnnouncer({ message }) {
  return (
    <div aria-live="assertive" role="status" className="visually-hidden">
      {message}
    </div>
  )
}
