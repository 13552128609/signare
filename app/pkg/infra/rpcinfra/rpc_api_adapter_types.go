package rpcinfra

import (
	"errors"
	"fmt"

	"github.com/hyperledger-labs/signare/app/pkg/usecases/hsmconnector"
)

// GenerateAccountRequestParams request definition
type GenerateAccountRequestParams struct {
	// ApplicationID requesting the Ethereum account generation.
	ApplicationID string
}

// GenerateAccountsV2RequestParams request definition for eth_generateAccountsV2
// It supports generating one ECDSA key-pair and optionally additional PQ key-pairs.
type GenerateAccountsV2RequestParams struct {
	// ApplicationID requesting the key generation.
	ApplicationID string
	// PQ indicates whether PQ key-pairs should be generated in addition to the ECDSA key-pair.
	PQ bool `json:"pq"`
	// Algorithms is the list of PQ algorithms to use. Its length determines how many PQ key-pairs are generated.
	Algorithms []string `json:"algorithms,omitempty"`
}

// SetParamsFrom populates the struct from the raw JSON-RPC params.
func (p *GenerateAccountsV2RequestParams) SetParamsFrom(params []any) error {
	if len(params) == 0 {
		// No additional parameters provided: leave PQ=false and Algorithms=nil.
		return nil
	}
	if len(params) != 1 {
		return fmt.Errorf("only one object is expected")
	}
	paramMap, ok := params[0].(map[string]any)
	if !ok {
		return fmt.Errorf("params[0] must be an object")
	}

	if pqParam, ok := paramMap["pq"]; ok {
		pq, okBool := pqParam.(bool)
		if !okBool {
			return errors.New("[pq] must be of type bool")
		}
		p.PQ = pq
	}

	if algParam, ok := paramMap["algorithms"]; ok {
		algSlice, okSlice := algParam.([]any)
		if !okSlice {
			return errors.New("[algorithms] must be an array")
		}
		algorithms := make([]string, 0, len(algSlice))
		for _, v := range algSlice {
			alg, okStr := v.(string)
			if !okStr {
				return errors.New("[algorithms] elements must be of type string")
			}
			algorithms = append(algorithms, alg)
		}
		p.Algorithms = algorithms
	}
	return nil
}

// ValidateParams validates the GenerateAccountsV2RequestParams.
func (p *GenerateAccountsV2RequestParams) ValidateParams() error {
	// If PQ is false, algorithms is ignored.
	// If PQ is true and no algorithms are provided, it's still acceptable
	// (it will generate only one ECDSA key-pair).
	return nil
}

// GenerateAccountsV2Response response definition for eth_generateAccountsV2
type GenerateAccountsV2Response struct {
	Keys []hsmconnector.GeneratedKey `json:"keys"`
}

// RemoveAccountRequestParams request definition
type RemoveAccountRequestParams struct {
	// ApplicationID requesting the Ethereum account removal.
	ApplicationID string
	// Address is the Ethereum account to be removed.
	Address string `json:"address"`
}

func (p *RemoveAccountRequestParams) SetParamsFrom(params []any) error {
	if len(params) != 1 {
		return fmt.Errorf("only one object is expected")
	}
	paramMap := params[0].(map[string]any)
	addressParam, ok := paramMap["address"]
	if !ok {
		return errors.New("missing required field [address]")
	}
	address, ok := addressParam.(string)
	if !ok {
		return errors.New("[address] must be of type string")
	}
	p.Address = address
	return nil
}

func (p *RemoveAccountRequestParams) ValidateParams() error {
	if len(p.Address) == 0 {
		return errors.New("[address] cannot be nil")
	}
	return nil
}

// ListAccountsRequestParams request definition
type ListAccountsRequestParams struct {
	ApplicationID string
}

// SignTXRequestParams request definition
type SignTXRequestParams struct {
	ApplicationID string
	// From address
	From string `json:"from"`
	// To address
	To *string `json:"to"`
	// Gas amount to use for transaction execution
	Gas *string `json:"gas"`
	// GasPrice to use for each paid gas
	GasPrice *string `json:"gasPrice"`
	// Value amount sent with this transaction
	Value *string `json:"value"`
	// Data arguments packed according to json rpc standard
	Data string `json:"data"`
	// Nonce integer to identify request
	Nonce string `json:"nonce"`
}

func (p *SignTXRequestParams) SetParamsFrom(params []any) error {
	if len(params) != 1 {
		return fmt.Errorf("only one object is expected")
	}
	paramMap := params[0].(map[string]any)

	// Required fields
	fromParam, ok := paramMap["from"]
	if !ok {
		return errors.New("missing required field [from]")
	}
	from, ok := fromParam.(string)
	if !ok {
		return errors.New("[from] must be of type string")
	}
	p.From = from

	dataParam, ok := paramMap["data"]
	if !ok {
		return errors.New("missing required field [data]")
	}
	data, ok := dataParam.(string)
	if !ok {
		return errors.New("[data] must be of type string")
	}
	p.Data = data

	nonceParam, ok := paramMap["nonce"]
	if !ok {
		return errors.New("missing required field [nonce]")
	}
	nonce, ok := nonceParam.(string)
	if !ok {
		return errors.New("[nonce] must be of type string")
	}
	p.Nonce = nonce

	// Optional fields
	var to, gas, gasPrice, value string

	toParam, ok := paramMap["to"]
	if ok {
		to, ok = toParam.(string)
		if !ok {
			return errors.New("[to] must be of type string")
		}
		p.To = &to
	}

	gasParam, ok := paramMap["gas"]
	if ok {
		gas, ok = gasParam.(string)
		if !ok {
			return errors.New("[gas] must be of type string")
		}
		p.Gas = &gas
	}

	gasPriceParam, ok := paramMap["gasPrice"]
	if ok {
		gasPrice, ok = gasPriceParam.(string)
		if !ok {
			return errors.New("[gasPrice] must be of type string")
		}
		p.GasPrice = &gasPrice
	}

	valueParam, ok := paramMap["value"]
	if ok {
		value, ok = valueParam.(string)
		if !ok {
			return errors.New("[value] must be of type string")
		}
		p.Value = &value
	}
	return nil
}

func (p *SignTXRequestParams) ValidateParams() error {
	if len(p.From) == 0 {
		return errors.New("[from] cannot be nil")
	}
	if len(p.Nonce) == 0 {
		return errors.New("[nonce] cannot be nil")
	}
	return nil
}
