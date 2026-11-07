/** A translation table for one area: exactly the Korean table's keys, any string values. */
export type Translation<T> = { readonly [K in keyof T]: string };
