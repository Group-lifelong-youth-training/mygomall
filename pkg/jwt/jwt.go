package jwt

type JWT struct {
	SigningKey []byte
}

func NewJWT(SigningKey []byte) *JWT {
	return &JWT{
		SigningKey,
	}
}
