export const A = ({ html }: { html: string }) => <div dangerouslySetInnerHTML={{__html: html}} />;  // expect: react-raw-html
export const B = ({ html }: { html: string }) => <div>{html}</div>;  // ok
export const C = ({ html }: { html: string }) => { const clean = DOMPurify.sanitize(html); return <div dangerouslySetInnerHTML={{__html: clean}} />; };  // ok
