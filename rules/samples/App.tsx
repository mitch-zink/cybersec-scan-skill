export const A = ({ html }: { html: string }) => <div dangerouslySetInnerHTML={{__html: html}} />;  // expect: react-raw-html
export const B = ({ html }: { html: string }) => <div>{html}</div>;  // ok
