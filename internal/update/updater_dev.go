package update

import "errors"

type devUpdater struct{}

func (u *devUpdater) Description() string {
	return "development build (update not supported)"
}

func (u *devUpdater) Update(_ ReleaseInfo) error {
	return errors.New("development build — update not supported. Build from source with 'make build'")
}
