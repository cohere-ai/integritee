package public.intel.ita.tdxutils

# Local stand-in for the ITA-provided utility function. ITA defines
# tdxutils.is_mrtd on the server; this mirrors it so opa check/eval can
# exercise policies that reference it.
is_mrtd(claims, measurements) if {
	some measurement in measurements
	measurement.key == claims.tdx_mrtd
}
