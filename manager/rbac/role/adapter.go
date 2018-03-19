package role

import (
	"github.com/jinzhu/gorm"
)

type Rule struct {
	PType string `gorm:"size:100"`
	V0    string `gorm:"size:100"`
	V1    string `gorm:"size:100"`
	V2    string `gorm:"size:100"`
	V3    string `gorm:"size:100"`
	V4    string `gorm:"size:100"`
	V5    string `gorm:"size:100"`
}

func (c *Rule) TableName() string {
	return "rule" //as Gorm keeps table names are plural, and we love consistency
}

// Adapter represents the Gorm adapter for rule storage.
type Adapter struct {
	db *gorm.DB
}

func newAdapter(db *gorm.DB) *Adapter {
	a := &Adapter{}
	a.db = db
	a.createTable()
	return a
}

// SaveRule saves rule to database.
func (a *Adapter) SaveRule(model Model) error {
	a.dropTable()
	a.createTable()

	for ptype, ast := range model["p"] {
		for _, rule := range ast.Rule {
			line := saveRuleLine(ptype, rule)
			err := a.db.Create(&line).Error
			if err != nil {
				return err
			}
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Rule {
			line := saveRuleLine(ptype, rule)
			err := a.db.Create(&line).Error
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// AddRule adds a rule to the storage.
func (a *Adapter) AddRule(sec string, ptype string, rule []string) error {
	line := saveRuleLine(ptype, rule)
	err := a.db.Create(&line).Error
	return err
}

func saveRuleLine(ptype string, rule []string) Rule {
	line := Rule{}

	line.PType = ptype
	if len(rule) > 0 {
		line.V0 = rule[0]
	}
	if len(rule) > 1 {
		line.V1 = rule[1]
	}
	if len(rule) > 2 {
		line.V2 = rule[2]
	}
	if len(rule) > 3 {
		line.V3 = rule[3]
	}
	if len(rule) > 4 {
		line.V4 = rule[4]
	}
	if len(rule) > 5 {
		line.V5 = rule[5]
	}

	return line
}

func (a *Adapter) createTable() {
	if a.db.HasTable(&Rule{}) {
		return
	}

	err := a.db.CreateTable(&Rule{}).Error
	if err != nil {
		panic(err)
	}
}

func (a *Adapter) dropTable() {
	err := a.db.DropTable(&Rule{}).Error
	if err != nil {
		panic(err)
	}
}

// LoadRule loads rule from database.
func (a *Adapter) LoadRule(model Model) error {
	var lines []Rule
	err := a.db.Find(&lines).Error
	if err != nil {
		return err
	}

	for _, line := range lines {
		loadRuleLine(line, model)
	}

	return nil
}

func loadRuleLine(line Rule, model Model) {
	lineText := line.PType
	if line.V0 != "" {
		lineText += ", " + line.V0
	}
	if line.V1 != "" {
		lineText += ", " + line.V1
	}
	if line.V2 != "" {
		lineText += ", " + line.V2
	}
	if line.V3 != "" {
		lineText += ", " + line.V3
	}
	if line.V4 != "" {
		lineText += ", " + line.V4
	}
	if line.V5 != "" {
		lineText += ", " + line.V5
	}

	loadRuleLineToModel(lineText, model)
}

// RemoveRule removes a rule from the storage.
func (a *Adapter) RemoveRule(sec string, ptype string, rule []string) error {
	line := saveRuleLine(ptype, rule)
	err := rawDelete(a.db, line)
	return err
}

// RemoveFilteredRule removes rules that match the filter from the storage.
func (a *Adapter) RemoveFilteredRule(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	line := Rule{}

	line.PType = ptype
	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		line.V0 = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		line.V1 = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		line.V2 = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		line.V3 = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		line.V4 = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		line.V5 = fieldValues[5-fieldIndex]
	}
	err := rawDeleteAll(a.db, line)
	return err
}

func rawDelete(db *gorm.DB, line Rule) error {
	err := db.Delete(Rule{}, "p_type = ? and v0 = ?"+
		" and v1 = ? and v2 = ? and v3 = ? and v4 = ? and v5 = ?",
		line.PType, line.V0, line.V1, line.V2, line.V3, line.V4, line.V5).Error
	return err
}

func rawDeleteAll(db *gorm.DB, line Rule) error {
	queryArgs := []interface{}{line.PType}

	queryStr := "p_type = ?"
	if line.V0 != "" {
		queryStr += " and v0 = ?"
		queryArgs = append(queryArgs, line.V0)
	}
	if line.V1 != "" {
		queryStr += " and v1 = ?"
		queryArgs = append(queryArgs, line.V1)
	}
	if line.V2 != "" {
		queryStr += " and v2 = ?"
		queryArgs = append(queryArgs, line.V2)
	}
	if line.V3 != "" {
		queryStr += " and v3 = ?"
		queryArgs = append(queryArgs, line.V3)
	}
	if line.V4 != "" {
		queryStr += " and v4 = ?"
		queryArgs = append(queryArgs, line.V4)
	}
	if line.V5 != "" {
		queryStr += " and v5 = ?"
		queryArgs = append(queryArgs, line.V5)
	}
	args := append([]interface{}{queryStr}, queryArgs...)
	err := db.Delete(Rule{}, args...).Error
	return err
}
