/// Clears every input of the page (the DOM keeps no typed secret once it was sent or the step moved on).
export function clearInputs(): void {
  for (const input of document.querySelectorAll<HTMLInputElement>('input[data-field]')) input.value = '';
}
