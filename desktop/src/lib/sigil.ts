import { fnv1a, mulberry32 } from './rng';

/** 11×11 left-right symmetric pixel picture derived from a device fingerprint (DESIGN.md §5.4).
 *  Inviter and invitee compute the same cells from the same fingerprint. */
export function sigilCells(fp: string): Array<[number, number]> {
  const rn = mulberry32(fnv1a(fp));
  const cells: Array<[number, number]> = [];
  for (let y = 0; y < 11; y++) {
    for (let x = 0; x < 6; x++) {
      if (rn() < 0.48) {
        cells.push([x, y]);
        if (x < 5) cells.push([10 - x, y]);
      }
    }
  }
  return cells;
}

/** The 9×9 ring-and-slash logo from the mockup. */
export function logoCells(): Array<[number, number]> {
  const cells: Array<[number, number]> = [];
  for (let y = 0; y < 9; y++) {
    for (let x = 0; x < 9; x++) {
      const d = Math.hypot(x - 4, y - 4);
      if (Math.abs(d - 3.6) < 0.62 || (x + y === 8 && d < 3.2)) cells.push([x, y]);
    }
  }
  return cells;
}
