"""Exact ordered seven-column table differences; no I/O or value normalization."""


def table_delta(before: list, after: list) -> dict:
    for table in (before, after):
        if type(table) is not list:
            raise ValueError("table must be a list")
        for row in table:
            if type(row) is not list or len(row) != 7 or any(type(cell) is not str for cell in row):
                raise ValueError("row must contain seven strings")
    shared = min(len(before), len(after))
    return {
        "before_count": len(before), "after_count": len(after),
        "changed_cells": [[row, column] for row in range(shared) for column in range(7)
                          if before[row][column] != after[row][column]],
        "added_rows": list(range(shared, len(after))),
        "removed_rows": list(range(shared, len(before))),
    }
