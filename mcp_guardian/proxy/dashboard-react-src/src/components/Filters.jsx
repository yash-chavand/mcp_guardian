import React from 'react'

const FILTERS = [
  { key: 'all', label: 'All' },
  { key: 'blocked', label: 'Blocked' },
  { key: 'allowed', label: 'Allowed' },
]

export default function Filters({ filter, onFilterChange, search, onSearchChange }) {
  return (
    <div className="filters-row">
      <div className="filter-group" role="group" aria-label="Filter by decision">
        {FILTERS.map(f => (
          <button
            key={f.key}
            type="button"
            className={`filter-btn ${filter === f.key ? 'active' : ''}`}
            aria-pressed={filter === f.key}
            onClick={() => onFilterChange(f.key)}
          >
            {f.label}
          </button>
        ))}
      </div>
      <div className="search-group">
        <label htmlFor="session-search" className="visually-hidden">Search by session ID or tool name</label>
        <input
          id="session-search"
          type="search"
          placeholder="Search session or tool…"
          value={search}
          onChange={e => onSearchChange(e.target.value)}
          className="search-input"
        />
      </div>
    </div>
  )
}
