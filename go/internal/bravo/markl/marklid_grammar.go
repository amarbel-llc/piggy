package markl

import _ "embed"

// MarklIdGrammar is the langlang-validated PEG grammar formalizing the
// markl-id text form (RFC 0002 §2, §2.1). See marklid.peg for the
// grammar itself and its sync obligation to RFC 0002. Validated by
// `just validate-grammar` (well-formedness) and `just
// test-grammar-vectors` (real conformance vectors parse via the
// intended production, piggy#220).
//
//go:embed marklid.peg
var MarklIdGrammar string
