using System.Text;
using System.IO;
using System;
using System.Security.Cryptography;

public class Util//Класс с функциями
{
    public Util()
    {
    }

    internal static readonly char[] chars =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".ToCharArray();//Символы ключа
    //"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".ToCharArray();

    public static uint ConvertStringToUInt(string Input)// Функция перевода символов в байты
    {
        uint output;//Число, которое будет переведенными в байты символами
        output = ((uint)Input[0]);// Первый символ
        output += ((uint)Input[1] << 8);// Второй символ
        output += ((uint)Input[2] << 16);// Третий символ
        output += ((uint)Input[3] << 24);// Четвертый символ
        return output;
    }

    public static string ConvertUIntToString(uint Input)
    {
        System.Text.StringBuilder output = new System.Text.StringBuilder();//Подготовка к переводу числа в строку
        output.Append((char)((Input & 0xFF)));// Первый символ
        output.Append((char)((Input >> 8) & 0xFF));// Второй символ
        output.Append((char)((Input >> 16) & 0xFF));// Третий символ
        output.Append((char)((Input >> 24) & 0xFF));// Четвертый символ
        return output.ToString();
    }

    public string GenerateKey()
    {
        const int length = 16;//Длина ключа
        byte[] data = new byte[4 * length];//Создание массива байтов
        using (var crypto = RandomNumberGenerator.Create())//Использование криптостойкого генератора
        {
            crypto.GetBytes(data);//Заполнение массива байтами
        }
        StringBuilder result = new StringBuilder(length);//Создание строки ключа
        for (int i = 0; i < length; i++)
        {
            var rnd = BitConverter.ToUInt32(data, i * 4);//Конвертация битов в int
            var idx = rnd % chars.Length;//Получения индекса символа ключа

            result.Append(chars[idx]);//Добавление символа в массив ключа
        }

        return result.ToString();
    }
}


public class Tea//Класс алгоритма ТЕА
{
    public Tea()
    {
    }

    public string EncryptString(string Data, string Key)//Функция шифровки
    {
        if (Data.Length == 0)//Проверка существования сообщения
            throw new ArgumentException("Data must be at least 1 character in length.");

        uint[] formattedKey = FormatKey(Key);//Форматирования ключа

        if (Data.Length % 2 != 0) Data += '\0';	//Добавление нулевых байтов
        byte[] dataBytes = System.Text.ASCIIEncoding.ASCII.GetBytes(Data);//Создание байтового массива из 
                                                                          //кодируемого сообщения
        string cipher = string.Empty;//Строка
        uint[] tempData = new uint[2];//Создание блока для кодирования
        for (int i = 0; i < dataBytes.Length; i += 2)//Цикл кодировки
        {
            tempData[0] = dataBytes[i];
            tempData[1] = dataBytes[i + 1];//Заполнение массива
            code(tempData, formattedKey);//Вызов шифровки
            cipher += Util.ConvertUIntToString(tempData[0]) + Util.ConvertUIntToString(tempData[1]);
        }

        return cipher;
    }

    public string Decrypt(string Data, string Key)//Функция дешифровки
    {
        uint[] formattedKey = FormatKey(Key);//Форматирование ключа

        int x = 0;
        uint[] tempData = new uint[2];//Создание блока для декодирования
        byte[] dataBytes = new byte[Data.Length / 8 * 2];//Создание байтового массива
        for (int i = 0; i < Data.Length; i += 8)//Цикл декодировки
        {
            tempData[0] = Util.ConvertStringToUInt(Data.Substring(i, 4));
            tempData[1] = Util.ConvertStringToUInt(Data.Substring(i + 4, 4));//Заполнение массива
            decode(tempData, formattedKey);//Вызов дешифровки
            dataBytes[x++] = (byte)tempData[0];
            dataBytes[x++] = (byte)tempData[1];//Форматирование в байты
        }

        string decipheredString = System.Text.ASCIIEncoding.ASCII.GetString(dataBytes, 0, dataBytes.Length);//Форматирование байтов в сообщение
        if (decipheredString[decipheredString.Length - 1] == '\0') // Удаление нулевых байтов
            decipheredString = decipheredString.Substring(0, decipheredString.Length - 1);
        return decipheredString;
    }

    public uint[] FormatKey(string Key)//Форматирования ключа для использования в алгоритмах TEA
    {
        if (Key.Length == 0)//Проверки существования ключа
            throw new ArgumentException("Key must be between 1 and 16 characters in length");

        Key = Key.PadRight(16, ' ').Substring(0, 16); // Если ключ менее 16 символов, добавление пробелов
        uint[] formattedKey = new uint[4];//Создание массива для форматированного ключа

        // Цикл форматирования ключа
        int j = 0;
        for (int i = 0; i < Key.Length; i += 4)
            formattedKey[j++] = Util.ConvertStringToUInt(Key.Substring(i, 4));

        return formattedKey;
    }

    public void code(uint[] v, uint[] k)//Кодировка ТЕА
    {
        uint y = v[0];
        uint z = v[1];
        uint sum = 0;
        uint delta = 0x9e3779b9;
        uint n = 32;

        while (n-- > 0)
        {
            sum += delta;
            y += (z << 4) + k[0] ^ z + sum ^ (z >> 5) + k[1];
            z += (y << 4) + k[2] ^ y + sum ^ (y >> 5) + k[3];
        }

        v[0] = y;
        v[1] = z;
    }

    public void decode(uint[] v, uint[] k)//Декодировка ТЕА
    {
        uint n = 32;
        uint sum;
        uint y = v[0];
        uint z = v[1];
        uint delta = 0x9e3779b9;

        sum = delta << 5;

        while (n-- > 0)
        {
            z -= (y << 4) + k[2] ^ y + sum ^ (y >> 5) + k[3];
            y -= (z << 4) + k[0] ^ z + sum ^ (z >> 5) + k[1];
            sum -= delta;
        }

        v[0] = y;
        v[1] = z;
    }
}
class MainProgram
{

    static void Main(string[] args)
    {   //Палёв А.Н. ПМИб-1902а
        string key;//Ключ
        string file1 = Path.GetFullPath(args[0]);//Файл, который будет использоваться в ТЕА
        string file2 = Path.GetFullPath(args[1]);//Файл ключа
        string text = System.IO.File.ReadAllText(file1);//Текст для использования

        Util U = new Util();
        Console.WriteLine("Generate a key? 1-yes else-no");//Генерировать ключ или использовать уже существующий
        int t = Convert.ToInt32(Console.ReadLine());

        if (t == 1)//Генерируем ключ и сохраняем его
        {
            key = U.GenerateKey();
            File.WriteAllText(@"D:\Works\IB\TEA\key.txt", key);
        }
        else {key = System.IO.File.ReadAllText(file2); }//Иначе загружаем из файла

        Tea cipher = new Tea();
        Console.WriteLine("Key: {0}", key);//Вывод ключа на консоль
        Console.WriteLine("Text: {0}", text);//Вывод текста на экран
        Console.WriteLine("Cipher(1) or decipher(2)?");//Выбор операции
        t = Convert.ToInt32(Console.ReadLine());

        if (t == 1)//Шифровка
        {
            string ciph = cipher.EncryptString(text, key);
            string path = (@"D:\Works\IB\TEA\text.txt.enc");//Задание определенного места для записи
            File.WriteAllText(path, ciph);//Запись в файл
        }

        else if (t == 2)//Дешифровка
        {
            string path1 = (@"D:\Works\IB\TEA\text.txt");
            string deciph = cipher.Decrypt(text, key);
            if (File.Exists(path1))//Если файл с текстом существует, то сохранить в другой
            { File.WriteAllText((@"D:\Works\IB\TEA\text().txt"), deciph); }//Запись в строго определенное место
            else
            { File.WriteAllText(path1, deciph);}
        }

        Console.WriteLine("Ciphering Done");
    }
}

