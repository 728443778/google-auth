defmodule TOTP do
  @moduledoc """
  根据 google 验证器的原理，elixir的一个实现
  生成一个一次性密码 TOTP.getPassword("GVCDKM2FIFBDSQSE", :sha|:sha256|:sha512)
  验证密码  TOTP.verifyCode("input password", "secret", :sha|:sha256|:sha512)
  """
  use Bitwise

  @giftPower [1,10,100,1000, 10000, 100000,1000000,10000000, 100000000]

  def getCurrentTimestamp() do
    {first, second, _} = :erlang.timestamp
    first * 1000000 + second
  end

  def getCount(step \\ 30) do
    Integer.floor_div(getCurrentTimestamp(), step)
  end

  def truncate(hash, length \\ 6) do
    hash = :binary.bin_to_list(hash)
    offset = List.last(hash) &&& 0xf
    binary = ((Enum.fetch!(hash, offset) &&& 0x7f) <<< 24) |||
            ((Enum.fetch!(hash, offset+1) &&& 0xff) <<< 16) |||
            ((Enum.fetch!(hash, offset+2) &&& 0xff) <<< 8) |||
            (Enum.fetch!(hash, offset+3) &&& 0xff)
    digits = Enum.fetch!(@giftPower, length)
    password = Integer.mod(binary, digits)
    password = Integer.to_string(password)
    if String.length(password) < length do
      String.duplicate("0", length - String.length(password)) <> password
    else
      password
    end
  end

  def passwordByHOTP(counter, secret \\ "GVCDKM2FIFBDSQSE",shaAlgo \\ :sha, passwdLength \\ 6) do
    secret = Base.decode32!(secret)
    list = List.duplicate(0, 8)
    {list, _} = Enum.map_reduce(list, counter, fn _, counter ->
      x = counter &&& 0xFF
      counter = counter >>> 8
      {x, counter}
    end)
    moveFac = Enum.reverse(list) |> :erlang.list_to_binary
    hash = :crypto.hmac(shaAlgo, secret, moveFac)
    truncate(hash, passwdLength)
  end

  # secret
  def getPassword(secret \\ "GVCDKM2FIFBDSQSE",shaAlgo \\ :sha, passwdLength \\ 6, step \\ 30) do
    step = getCount(step)
    passwordByHOTP(step, secret, shaAlgo, passwdLength)
  end

  def createSecret() do
    prefix = getCurrentTimestamp() |> Integer.to_string(16) #用unix 时间磋的16进制作为前缀
    last = :erlang.unique_integer |> Integer.to_string(16) |> String.slice(-2, 2)
    Base.encode32(prefix <> last)
  end

  def qrcodeUrl(secret, username \\ "", org  \\ "") do
    "otpauth://totp/" <>username <>"?issuer="<>org<>"&secret=" <> secret
  end

  def verifyPassword(inputCode, secret \\ "GVCDKM2FIFBDSQSE",shaAlgo\\ :sha, length \\ 6, step \\ 30) do
    inputCode == getPassword(secret,shaAlgo, length, step)
  end
end
