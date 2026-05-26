package streamjson

import (
	"encoding/json"
	"io"
	"reflect"
	"sort"
)

type Field struct {
	Name  string
	Value any
}

func WriteObject(writer io.Writer, fields []Field) error {
	if _, err := io.WriteString(writer, "{"); err != nil {
		return err
	}
	for index, field := range fields {
		if index > 0 {
			if _, err := io.WriteString(writer, ","); err != nil {
				return err
			}
		}
		if err := writeScalar(writer, field.Name); err != nil {
			return err
		}
		if _, err := io.WriteString(writer, ":"); err != nil {
			return err
		}
		if err := WriteValue(writer, field.Value); err != nil {
			return err
		}
	}
	_, err := io.WriteString(writer, "}")
	return err
}

func WriteValue(writer io.Writer, value any) error {
	if value == nil {
		_, err := io.WriteString(writer, "null")
		return err
	}
	reflected := reflect.ValueOf(value)
	if reflected.Kind() == reflect.Pointer {
		if reflected.IsNil() {
			_, err := io.WriteString(writer, "null")
			return err
		}
	}
	if isStreamableSlice(reflected) {
		return writeSlice(writer, reflected)
	}
	if reflected.Kind() == reflect.Map && reflected.Type().Key().Kind() == reflect.String {
		return writeStringKeyMap(writer, reflected)
	}
	return writeScalar(writer, value)
}

func writeSlice(writer io.Writer, value reflect.Value) error {
	if value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if value.IsNil() {
		_, err := io.WriteString(writer, "null")
		return err
	}
	if _, err := io.WriteString(writer, "["); err != nil {
		return err
	}
	for index := 0; index < value.Len(); index++ {
		if index > 0 {
			if _, err := io.WriteString(writer, ","); err != nil {
				return err
			}
		}
		if err := WriteValue(writer, value.Index(index).Interface()); err != nil {
			return err
		}
	}
	_, err := io.WriteString(writer, "]")
	return err
}

func writeStringKeyMap(writer io.Writer, value reflect.Value) error {
	if value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if value.IsNil() {
		_, err := io.WriteString(writer, "null")
		return err
	}
	if _, err := io.WriteString(writer, "{"); err != nil {
		return err
	}
	keys := value.MapKeys()
	sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
	for index, key := range keys {
		if index > 0 {
			if _, err := io.WriteString(writer, ","); err != nil {
				return err
			}
		}
		if err := writeScalar(writer, key.String()); err != nil {
			return err
		}
		if _, err := io.WriteString(writer, ":"); err != nil {
			return err
		}
		if err := WriteValue(writer, value.MapIndex(key).Interface()); err != nil {
			return err
		}
	}
	_, err := io.WriteString(writer, "}")
	return err
}

func writeScalar(writer io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = writer.Write(data)
	return err
}

func isStreamableSlice(value reflect.Value) bool {
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return false
		}
		value = value.Elem()
	}
	return value.Kind() == reflect.Slice || value.Kind() == reflect.Array
}
