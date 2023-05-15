package models

import (
	"gorm.io/gorm"
)

type LpPair struct {
	gorm.Model
	LPAddress       string `gorm:"lp_address"`
	LPPairA         string
	LPPairB         string
	HasLiquidity    bool
	TradingEnabled    bool
	EventsCatchedID uint
}
