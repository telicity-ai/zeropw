import { useEffect, useRef, useState, type SyntheticEvent } from 'react';

/** Defaults may arrive asynchronously. After a user toggle or validation reveal, preserve the
 * chosen disclosure state: clearing an input error must never hide the input being repaired. */
export function useDisclosure(defaultOpen: boolean) {
  const [open, setOpen] = useState(defaultOpen);
  const touched = useRef(false);
  useEffect(() => { if (!touched.current) setOpen(defaultOpen); }, [defaultOpen]);
  const reveal = () => { touched.current = true; setOpen(true); };
  const onSummaryClick = () => { touched.current = true; };
  const onToggle = (event: SyntheticEvent<HTMLDetailsElement>) => setOpen(event.currentTarget.open);
  return { open, reveal, onSummaryClick, onToggle };
}
