package aws

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func isResourceTimeoutError(err error) bool {
	timeoutErr, ok := err.(*resource.TimeoutError)
	return ok && timeoutErr.LastError == nil
}
