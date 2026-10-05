// Package pigpen_resolve turns a pigpen pointer document into the
// recipient set it names, by running the pointer's resolver plugin
// (piggy RFC 0010).
//
// It lives apart from the pigpen package because it runs a subprocess:
// the pigpen core imports no os/exec and stays buildable for
// GOOS=js GOARCH=wasm (RFC 0008 §7).
//
// Two deliberate differences from the Rust CLI's resolution
// (crates/piggy/src/pigpen_pointer.rs):
//
//   - No cache. A consumer that wants to notice a changed recipient set
//     needs a live answer; whether and how long to cache is its decision.
//   - The resolver runs under the caller's context, so a timeout or
//     cancellation kills it (the CLI has none, piggy#218).
package pigpen_resolve

//go:generate dagnabit export
