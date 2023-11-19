using LargeInt;
using System.Text;

Console.OutputEncoding = Encoding.UTF8;

Console.WriteLine("Введіть розмір блоку у байтах:");
int blockLength = Int32.Parse(Console.ReadLine());
int padding = 3;

if (blockLength-padding<=0)
{
    Console.WriteLine("Занадто великий padding (або замала довжина блоку)");
    return;
}

Console.WriteLine("Введіть назву файлу який треба зашифрувати:");
string fileName = Console.ReadLine();

var keyPair = GenerateRSAKeys(((blockLength - padding) * 8) / 2 + 1 );

Console.WriteLine("Відкритий ключ (e, n):");
Console.WriteLine($"e = {keyPair.PublicKey.Exponent}");
Console.WriteLine($"n = {keyPair.PublicKey.Modulus}");
Console.WriteLine();

Console.WriteLine("Закритий ключ (d, n):");
Console.WriteLine($"d = {keyPair.PrivateKey.Exponent}");
Console.WriteLine($"n = {keyPair.PrivateKey.Modulus}\n");

using (var f = new FileStream(fileName, FileMode.Open, FileAccess.Read))
{
    using (var nf = File.Exists(fileName + "Encrypted") ? File.OpenWrite(fileName + "Encrypted") : File.Create(fileName.Split('.')[0] + "Encrypted.txt"))
    {
        byte[] buffer = new byte[blockLength - padding];
        byte[] toWrite = new byte[blockLength];
        int readed;
        do
        {
            readed = f.Read(buffer, 0, blockLength - padding);
            if (readed != blockLength - padding)
            {
                Array.Resize(ref buffer, readed);
            }
            BigInteger bi_data = new BigInteger(buffer);
            BigInteger bi_encrypted = bi_data.modPow(keyPair.PublicKey.Exponent, keyPair.PublicKey.Modulus);
            var b = bi_encrypted.getBytes();

            int lastIndex = Array.FindLastIndex(b, b => b != 0);
            byte pSize = (byte)(blockLength - (lastIndex + 1));

            toWrite[blockLength - 1] = pSize;
            b.CopyTo(toWrite, 0);

            nf.Write(toWrite, 0, blockLength);

            if (readed != blockLength - padding)
            {
                break;
            }
        }
        while(readed>0);

    }
}
List<byte> res = new();
using (var f = new FileStream(fileName.Split('.')[0] + "Encrypted.txt", FileMode.Open, FileAccess.Read))
{
    byte[] buffer = new byte[blockLength];

    while (f.Read(buffer, 0, blockLength) > 0)
    {
        BigInteger data = new BigInteger(buffer.Take(buffer.Length - buffer[buffer.Length-1]).ToArray());
        BigInteger bi_decrypted = data.modPow(keyPair.PrivateKey.Exponent, keyPair.PrivateKey.Modulus);

        res.AddRange(bi_decrypted.getBytes());
    }
}
string result = Encoding.UTF8.GetString(res.ToArray());
string original = File.ReadAllText(fileName);
Console.WriteLine(result.Equals(original)?"Все вірно":"Помилка");
//RSATest(100, keyPair);




static RSAKeyPair GenerateRSAKeys(int primeLength)
{
    BigInteger p = PrimeGenerator.GeneratePrimeNumber(primeLength);
    BigInteger q = PrimeGenerator.GeneratePrimeNumber(primeLength);

    BigInteger n = p * q;
    BigInteger phi = (p - 1) * (q - 1);
    BigInteger e = ChooseExponent(phi); //65537; 
    BigInteger d = CalculateD(e, phi);

    return new RSAKeyPair
    {
        PublicKey = new RSAParames { Exponent = e, Modulus = n },
        PrivateKey = new RSAParames { Exponent = d, Modulus = n }
    };
}

//e must be co-prime to phi and smaller than phi.
static BigInteger ChooseExponent(BigInteger phi)
{
    BigInteger e = 2;
    while (e < phi)
    {
        if (gcd(e, phi) == 1)
            break;
        else
            e+=1;
    }
    return e;
}

static BigInteger gcd(BigInteger a, BigInteger h)
{
    BigInteger temp;
    while (true)
    {
        temp = a % h;
        if (temp == 0)
            return h;
        a = h;
        h = temp;
    }
}

// Розширений алгоритм Евкліда (e*d%phi==1)
static BigInteger CalculateD(BigInteger e, BigInteger phi)
{
    BigInteger m0 = phi;
    BigInteger y = 0, x = 1;

    if (phi == 1)
        return 0;

    while (e > 1)
    {
        BigInteger q = e / phi;
        BigInteger t = phi;

        phi = e % phi;
        e = t;
        t = y;

        y = x - q * y;
        x = t;
    }

    if (x < 0)
        x += m0;

    return x;
}

static void RSATest(int rounds, RSAKeyPair keys)
{
    Random rand = new Random(1);
    byte[] val = new byte[64];

    BigInteger bi_e = keys.PublicKey.Exponent;
    BigInteger bi_d = keys.PrivateKey.Exponent;
    BigInteger bi_n = keys.PublicKey.Modulus;

    Console.WriteLine("e = " + bi_e.ToString(10));
    Console.WriteLine("d = " + bi_d.ToString(10));
    Console.WriteLine("n = " + bi_n.ToString(10) + "\n");

    for (int count = 0; count < rounds; count++)
    {
        int t1 = 0;
        while (t1 == 0)
            t1 = (int)(rand.NextDouble() * 65);

        bool done = false;
        while (!done)
        {
            for (int i = 0; i < 64; i++)
            {
                if (i < t1)
                    val[i] = (byte)(rand.NextDouble() * 256);
                else
                    val[i] = 0;

                if (val[i] != 0)
                    done = true;
            }
        }

        while (val[0] == 0)
            val[0] = (byte)(rand.NextDouble() * 256);

        Console.Write("Round = " + count);

        BigInteger bi_data = new BigInteger(val);
        BigInteger bi_encrypted = bi_data.modPow(bi_e, bi_n);
        BigInteger bi_decrypted = bi_encrypted.modPow(bi_d, bi_n);

        if (bi_decrypted != bi_data)
        {
            Console.WriteLine("\nError at round " + count);
            Console.WriteLine(bi_data + "\n");
            return;
        }
        Console.WriteLine(" <PASSED>.");
    }
}
class RSAKeyPair
{
    public RSAParames PublicKey { get; set; }
    public RSAParames PrivateKey { get; set; }
}
class RSAParames
{
    public BigInteger Exponent { get; set; }
    public BigInteger Modulus { get; set; }
}
