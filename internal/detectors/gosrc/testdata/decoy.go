package sample

import "fmt"

// config has a Model field, but with no AI SDK import in this file the
// detector must not treat the literal as a hosted model.
type config struct {
	Model string
}

func show() {
	c := config{Model: "sedan"}
	fmt.Println(c.Model)
}
