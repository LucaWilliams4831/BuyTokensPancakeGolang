package models

import (
	"gorm.io/gorm"
)

type EventsCatched struct {
	gorm.Model
	TxHash       string
	TokenAddress string
	TokenName string
	LPPairs      []*LpPair
}
