// Places: a project/environment pair as the vault shows it. A personal vault starts with one
// place, `personal/main` (made by the first run), shown simply as its project.

/** The place a new personal vault gets; any other place is shown as it is. */
export const PERSONAL_PROJECT = 'personal';
export const PERSONAL_ENV = 'main';

/** A place as lists show it: the project, and the environment unless it is the default one
 *  personal vaults use. */
export function placeLabel(project: string, environment: string): string {
  return environment === PERSONAL_ENV ? project : `${project} · ${environment}`;
}
