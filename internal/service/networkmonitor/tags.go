package networkmonitor

// Describes a tag.
type Tag struct {
	_ struct{} `type:"structure"`

	// The tag key.
	//
	// Constraints: Maximum length of 128 characters.
	Key *string `type:"string"`

	// The tag value.
	//
	// Constraints: Maximum length of 256 characters.
	Value *string `type:"string"`
}
