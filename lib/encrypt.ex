defmodule Encrypt do
  @aad "AES256GCM"
  @moduledoc """
  Documentation for Encrypt.
  """

  @doc """
  `generate_secret`
  Generates a random base64 encoded secret key.
  """
  def generate_secret do
    :crypto.strong_rand_bytes(16)
    |> :base64.encode()
  end

  def encrypt(val, key) do
    mode = :aes_gcm
    secret_key = :base64.decode(key)
    iv = :crypto.strong_rand_bytes(16)

    {ciphertext, ciphertag} =
      :crypto.block_encrypt(mode, secret_key, iv, {@aad, to_string(val), 16})

    (iv <> ciphertag <> ciphertext) |> :base64.encode()
  end

  def decrypt(ciphertext, key) do
    mode = :aes_gcm
    secret_key = :base64.decode(key)
    ciphertext = :base64.decode(ciphertext)
    <<iv::binary-16, tag::binary-16, ciphertext::binary>> = ciphertext
    :crypto.block_decrypt(mode, secret_key, iv, {@aad, ciphertext, tag})
  end
end
