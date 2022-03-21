<?php

namespace Brainstud\FileVault;

use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;

class FileVault
{
    /**
     * The storage disk.
     *
     * @var string
     */
    protected string $disk;

    /**
     * The encryption key.
     *
     * @var string
     */
    protected string $key;

    /**
     * The algorithm used for encryption.
     *
     * @var string
     */
    protected string $cipher;

    /**
     * The storage adapter.
     */
    protected $adapter;

    public function __construct()
    {
        $this->disk = config('file-vault.disk');
        $this->key = config('file-vault.key');
        $this->cipher = config('file-vault.cipher');
    }

    /**
     * Set the disk where the files are located.
     *
     * @param string $disk
     * @return $this
     */
    public function disk(string $disk): static
    {
        $this->disk = $disk;

        return $this;
    }

    /**
     * Set the encryption key.
     *
     * @param string $key
     * @return $this
     */
    public function key($key): static
    {
        $this->key = $key;

        return $this;
    }

    /**
     * Create a new encryption key for the given cipher.
     *
     * @return string
     * @throws \Exception
     */
    public static function generateKey(): string
    {
        return random_bytes(config('file-vault.cipher') === 'AES-128-CBC' ? 16 : 32);
    }

    /**
     * Encrypt the passed file and saves the result in a new file with ".enc" as suffix.
     *
     * @param string $sourceFile Path to file that should be encrypted, relative to the storage disk specified
     * @param string|null $destFile File name where the encrypted file should be written to, relative to the storage disk specified
     * @param bool $deleteSource Delete the source file after encrypting
     * @return $this
     * @throws \Exception
     */
    public function encrypt(string $sourceFile, ?string $destFile = null, bool $deleteSource = true): static
    {
        $this->registerServices();

        if (is_null($destFile)) {
            $destFile = "{$sourceFile}.enc";
        }

        $sourcePath = $this->getFilePath($sourceFile);
        $destPath = $this->getFilePath($destFile);

        // Create a new encrypter instance
        $encrypter = new FileEncrypter($this->key, $this->cipher);

        // If encryption is successful, delete the source file
        if ($encrypter->encrypt($sourcePath, $destPath) && $deleteSource) {
            Storage::disk($this->disk)->delete($sourceFile);
        }

        return $this;
    }

    /**
     * Encrypt the passed file and saves the result in a new file with ".enc" as suffix. The source file is not deleted.
     *
     * @param string $sourceFile Path to file that should be encrypted, relative to the storage disk specified
     * @param string|null $destFile File name where the encrypted file should be written to, relative to the storage disk specified
     * @return $this
     * @throws \Exception
     */
    public function encryptCopy(string $sourceFile, ?string $destFile = null): static
    {
        return self::encrypt($sourceFile, $destFile, false);
    }

    /**
     * Decrypt the passed file and saves the result in a new file, removing the
     * last 4 characters from file name.
     *
     * @param string $sourceFile Path to file that should be decrypted
     * @param string|null $destFile File name where the decrypted file should be written to.
     * @return $this
     * @throws \Exception
     */
    public function decrypt(string $sourceFile, ?string $destFile = null, bool $deleteSource = true): static
    {
        $this->registerServices();

        if (is_null($destFile)) {
            $destFile = Str::endsWith($sourceFile, '.enc')
                ? Str::replaceLast('.enc', '', $sourceFile)
                : $sourceFile . '.dec';
        }

        $sourcePath = $this->getFilePath($sourceFile);
        $destPath = $this->getFilePath($destFile);

        // Create a new encrypter instance
        $encrypter = new FileEncrypter($this->key, $this->cipher);

        // If decryption is successful, delete the source file
        if ($encrypter->decrypt($sourcePath, $destPath) && $deleteSource) {
            Storage::disk($this->disk)->delete($sourceFile);
        }

        return $this;
    }

    /**
     * Decrypt the passed file and saves the result in a new file, removing the
     * last 4 characters from file name. Keep the source file
     *
     * @param string $sourceFile Path to file that should be decrypted
     * @param string|null $destFile File name where the decrypted file should be written to.
     * @return $this
     * @throws \Exception
     */
    public function decryptCopy(string $sourceFile, ?string $destFile = null): static
    {
        return self::decrypt($sourceFile, $destFile, false);
    }

    /**
     * @throws \Exception
     */
    public function streamDecrypt($sourceFile): bool
    {
        $this->registerServices();

        $sourcePath = $this->getFilePath($sourceFile);

        // Create a new encrypter instance
        $encrypter = new FileEncrypter($this->key, $this->cipher);

        return $encrypter->decrypt($sourcePath, 'php://output');
    }

    protected function getFilePath($file): string
    {
        if ($this->isS3File()) {
            return "s3://{$this->adapter->getBucket()}/$file";
        }

        return Storage::disk($this->disk)->path($file);
    }

    protected function isS3File()
    {
        return $this->disk == 's3';
    }

    protected function setAdapter()
    {
        if ($this->adapter) {
            return;
        }

        $this->adapter = Storage::disk($this->disk)->getAdapter();
    }

    protected function registerServices()
    {
        $this->setAdapter();

        if ($this->isS3File()) {
            $client = $this->adapter->getClient();
            $client->registerStreamWrapper();
        }
    }
}
