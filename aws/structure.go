package aws

import "github.com/aws/aws-sdk-go/aws"

// Takes the result of flatmap.Expand for an array of strings
// and returns a []*string
func expandStringList(configured []interface{}) []*string {
	vs := make([]*string, 0, len(configured))
	for _, v := range configured {
		val, ok := v.(string)
		if ok && val != "" {
			vs = append(vs, aws.String(v.(string)))
		}
	}
	return vs
}

// Takes list of pointers to strings. Expand to an array
// of raw strings and returns a []interface{}
// to keep compatibility w/ schema.NewSetschema.NewSet
func flattenStringList(list []*string) []interface{} {
	vs := make([]interface{}, 0, len(list))
	for _, v := range list {
		vs = append(vs, *v)
	}
	return vs
}

func pointersMapToStringList(pointers map[string]*string) map[string]interface{} {
	list := make(map[string]interface{}, len(pointers))
	for i, v := range pointers {
		list[i] = *v
	}
	return list
}

func stringMapToPointers(m map[string]interface{}) map[string]*string {
	list := make(map[string]*string, len(m))
	for i, v := range m {
		list[i] = aws.String(v.(string))
	}
	return list
}
