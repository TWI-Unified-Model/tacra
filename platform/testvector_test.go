package platform

// Test vector of draft-novak-lamps-tacra-est, Appendix A: the enrollment of SEV-SNP run 20260926T234654Z, where
// SHA-512(binding_input) equals REPORT_DATA of the hardware report (github.com/nikolaichuk7/tacra-est).
const (
	tvHandleHex  = "e39ee18f47255556de29bc34d2fd4141ff5797d315b47cfbd0acc86c86ca8016"
	tvRRPID      = "https://ca1.tacra.example"
	tvTarget     = "https://db.tacra.example"
	tvSubjectHex = "3081dc3081830201003021311f301d06035504030c16776f726b6c6f61642e74616372612e6578616d706c653059301306072a8648ce3d020106082a8648ce3d03010703420004780c6a706be85e9cf18896723e396c49d6f84e1d8894eeab1846a1a433c78c42d364092885bcff56720e2c2f86535b1255ddbdd2fd69544d3a850a59482f17c4a000300a06082a8648ce3d0403020348003045022100b662273a1d0197775c4acfbc2d571532adba8ed87bde958dce08852584c89f210220152cc07fa4f24084189ab4f2c94846f5760685afe9d377cbe978d6b71a436502"
	tvDigestHex  = "cbff0ef7f48aac35df0698d3d171d2d50c175aa0d15f7dedc52cb225d753010f6386a9afb243a7a4a054d0ba0e1235c08a187fbe3bc512f90a937f8a82bf8beb"
)
