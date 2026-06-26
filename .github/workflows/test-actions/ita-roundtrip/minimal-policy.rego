package integritee_policy
import rego.v1
default match := false
match if { matches_tdx; matches_nvgpu }
matches_tdx if { input.tdx.tdx_is_debuggable == false }
matches_nvgpu if { true }
