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

// SignTXV2RequestParams extends SignTXRequestParams with an optional algorithm parameter.
// If algorithm is empty, implementations should default to ECDSA (KeyAlgorithmECDSAsecp256k1).
type SignTXV2RequestParams struct {
	SignTXRequestParams
	// Algorithm selects which algorithm should be used for signing.
	Algorithm string `json:"algorithm,omitempty"`
}

func (p *SignTXV2RequestParams) SetParamsFrom(params []any) error {
	// Reuse SignTXRequestParams parsing logic first.
	if err := (&p.SignTXRequestParams).SetParamsFrom(params); err != nil {
		return err
	}
	if len(params) != 1 {
		return fmt.Errorf("only one object is expected")
	}
	paramMap, ok := params[0].(map[string]any)
	if !ok {
		return fmt.Errorf("params[0] must be an object")
	}
	if algParam, ok := paramMap["algorithm"]; ok {
		alg, okStr := algParam.(string)
		if !okStr {
			return errors.New("[algorithm] must be of type string")
		}
		p.Algorithm = alg
	}
	return nil
}

func (p *SignTXV2RequestParams) ValidateParams() error {
	return (&p.SignTXRequestParams).ValidateParams()
}

// SignTXV2Response is the response definition for eth_signTransactionV2.
// It can return either a classical Ethereum signed transaction (ECDSA)
// or a PQ signature over the same txHash, depending on the algorithm used.
type SignTXV2Response struct {
	// SignedTx is the RLP-encoded Ethereum transaction when ECDSA is used.
	SignedTx *string `json:"signedTx,omitempty"`
	// TxHash is the hash of the Ethereum transaction payload that was signed.
	TxHash string `json:"txHash"`
	// Algorithm used for signing (e.g. "ECDSA-secp256k1", "ML-DSA-44").
	Algorithm string `json:"algorithm"`
	// Signature is the raw signature (hex-encoded) for non-ECDSA algorithms.
	// For ECDSA it may be empty, as the signature is already embedded in SignedTx.
	Signature *string `json:"signature,omitempty"`
}

// VerifyRequestParams request definition for eth_verify.
// It verifies a signature over arbitrary data using the key identified by (from, algorithm).
type VerifyRequestParams struct {
	ApplicationID string
	// From address identifying the key to use.
	From string `json:"from"`
	// Data is the signed payload (e.g., a hash) as hex string.
	Data string `json:"data"`
	// Signature is the signature over Data as hex string.
	Signature string `json:"signature"`
	// Algorithm selects which algorithm should be used for verification.
	// If empty, implementations should default to ECDSA (KeyAlgorithmECDSAsecp256k1).
	Algorithm string `json:"algorithm,omitempty"`
}

func (p *VerifyRequestParams) SetParamsFrom(params []any) error {
	if len(params) != 1 {
		return fmt.Errorf("only one object is expected")
	}
	paramMap, ok := params[0].(map[string]any)
	if !ok {
		return fmt.Errorf("params[0] must be an object")
	}

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

	sigParam, ok := paramMap["signature"]
	if !ok {
		return errors.New("missing required field [signature]")
	}
	sig, ok := sigParam.(string)
	if !ok {
		return errors.New("[signature] must be of type string")
	}
	p.Signature = sig

	if algParam, ok := paramMap["algorithm"]; ok {
		alg, okStr := algParam.(string)
		if !okStr {
			return errors.New("[algorithm] must be of type string")
		}
		p.Algorithm = alg
	}
	return nil
}

func (p *VerifyRequestParams) ValidateParams() error {
	if len(p.From) == 0 {
		return errors.New("[from] cannot be nil")
	}
	if len(p.Data) == 0 {
		return errors.New("[data] cannot be nil")
	}
	if len(p.Signature) == 0 {
		return errors.New("[signature] cannot be nil")
	}
	return nil
}

// VerifyResponse response definition for eth_verify.
type VerifyResponse struct {
	// Result is true if the signature is valid for the given data and key.
	Result bool `json:"result"`
	// PK is the public key used for verification, hex-encoded.
	PK string `json:"pk"`
}

// GetPKRequestParams request definition for eth_getpk.
// It retrieves the public key for the given (from, algorithm).
type GetPKRequestParams struct {
	ApplicationID string
	// From address identifying the key to use.
	From string `json:"from"`
	// Algorithm selects which algorithm should be used to locate the key.
	// If empty, implementations should default to ECDSA (KeyAlgorithmECDSAsecp256k1).
	Algorithm string `json:"algorithm,omitempty"`
}

func (p *GetPKRequestParams) SetParamsFrom(params []any) error {
	if len(params) != 1 {
		return fmt.Errorf("only one object is expected")
	}
	paramMap, ok := params[0].(map[string]any)
	if !ok {
		return fmt.Errorf("params[0] must be an object")
	}

	fromParam, ok := paramMap["from"]
	if !ok {
		return errors.New("missing required field [from]")
	}
	from, ok := fromParam.(string)
	if !ok {
		return errors.New("[from] must be of type string")
	}
	p.From = from

	if algParam, ok := paramMap["algorithm"]; ok {
		alg, okStr := algParam.(string)
		if !okStr {
			return errors.New("[algorithm] must be of type string")
		}
		p.Algorithm = alg
	}
	return nil
}

func (p *GetPKRequestParams) ValidateParams() error {
	if len(p.From) == 0 {
		return errors.New("[from] cannot be nil")
	}
	return nil
}

// GetPKResponse response definition for eth_getpk.
type GetPKResponse struct {
	// PK is the public key for the given (from, algorithm), hex-encoded.
	PK string `json:"pk"`
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
