var(key, iv) = QuantumCrytography.PostQuantumCryptography.GenerateKeyAndIV();

Console.WriteLine("Enter the value to encrypt");

string input = Console.ReadLine();
string encrypted = QuantumCrytography.PostQuantumCryptography.EncryptString(input, key, iv);
Console.WriteLine("Encrypted: " + encrypted);
string decrypted = QuantumCrytography.PostQuantumCryptography.DecryptString(encrypted, key, iv);
Console.WriteLine("decrypted: " + decrypted);
Console.WriteLine("Hit any key to exit");
Console.ReadKey();