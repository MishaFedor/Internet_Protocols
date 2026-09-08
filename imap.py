import imaplib
import email
from email.header import decode_header
import getpass
import sys
import argparse
from datetime import datetime
from tabulate import tabulate

def decode_mime_header(header_value):
    if header_value is None:
        return ""
    
    decoded_parts = []
    for part, encoding in decode_header(header_value):
        if isinstance(part, bytes):
            try:
                if encoding:
                    decoded_parts.append(part.decode(encoding))
                else:
                    decoded_parts.append(part.decode('utf-8', errors='ignore'))
            except (LookupError, UnicodeDecodeError):
                decoded_parts.append(part.decode('utf-8', errors='ignore'))
        else:
            decoded_parts.append(part)
    
    return ' '.join(decoded_parts)

def parse_email_date(date_str):
    if not date_str:
        return "Дата неизвестна"
    
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(date_str)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return date_str[:30] if len(date_str) > 30 else date_str

def get_attachments_info(msg):
    attachments = []
    
    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = str(part.get("Content-Disposition", ""))
            
            if "attachment" in content_disposition.lower():
                filename = part.get_filename()
                if filename:
                    filename = decode_mime_header(filename)
                
                size = len(part.get_payload(decode=True)) if part.get_payload(decode=True) else 0
                
                attachments.append({
                    'filename': filename or "Без имени",
                    'size': size
                })
    
    return attachments

def connect_imap(server, port, use_ssl, username, password):
    try:
        if use_ssl:
            connection = imaplib.IMAP4_SSL(server, port)
        else:
            connection = imaplib.IMAP4(server, port)
        
        connection.login(username, password)
        return connection
    except Exception as e:
        print(f"Ошибка подключения: {e}")
        sys.exit(1)

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Вывод информации о письмах в почтовом ящике",
        add_help=False
    )
    
    parser.add_argument("-h", "--help", action="help", help="Показать справку")
    parser.add_argument("--ssl", action="store_true", 
                       help="Разрешить использование SSL (по умолчанию не использовать)")
    parser.add_argument("-s", "--server", 
                       help="Адрес IMAP-сервера в формате адрес[:порт] (порт по умолчанию 143)")
    parser.add_argument("-n", nargs="+", metavar="N", 
                       help="Диапазон писем: N1 или N1 N2 (по умолчанию все)")
    parser.add_argument("-u", "--user", required=True, 
                       help="Имя пользователя (пароль будет запрошен позже)")
    
    args = parser.parse_args()
    
    if not args.server:
        print("Ошибка: Не указан адрес сервера. Используйте -s/--server")
        sys.exit(1)
    
    return args

def parse_range(range_args):
    if not range_args:
        return None, None
    
    if len(range_args) == 1:
        n1 = int(range_args[0])
        return n1, n1
    elif len(range_args) == 2:
        n1, n2 = map(int, range_args)
        if n1 > n2:
            print("Ошибка: Первое число диапазона должно быть меньше или равно второму")
            sys.exit(1)
        return n1, n2
    else:
        print("Ошибка: Неверный формат диапазона. Укажите N1 или N1 N2")
        sys.exit(1)

def main():
    args = parse_arguments()
    
    if ":" in args.server:
        server, port = args.server.split(":", 1)
        port = int(port)
    else:
        server = args.server
        port = 993 if args.ssl else 143
    
    password = getpass.getpass("Введите пароль: ")
    
    print(f"Подключение к {server}:{port}...")
    connection = connect_imap(server, port, args.ssl, args.user, password)
    
    try:
        status, messages_data = connection.select("INBOX")
        if status != "OK":
            print("Ошибка: Не удалось выбрать почтовый ящик INBOX")
            sys.exit(1)
        
        total_messages = int(messages_data[0])
        print(f"Всего писем в ящике: {total_messages}")
        
        start, end = parse_range(args.n)
        if start is None:
            start, end = 1, total_messages
        elif end is None:
            end = start
        
        if start > total_messages:
            print(f"Ошибка: Начальный номер {start} превышает общее количество писем {total_messages}")
            sys.exit(1)
        
        if end > total_messages:
            print(f"Предупреждение: Конечный номер {end} превышает {total_messages}, будет обработано до {total_messages}")
            end = total_messages
        
        print(f"Обработка писем с {start} по {end}\n")
        
        status, search_data = connection.search(None, f"{start}:{end}")
        if status != "OK":
            print("Ошибка при поиске писем")
            sys.exit(1)
        
        message_ids = search_data[0].split()
        print(f"Найдено писем для обработки: {len(message_ids)}\n")
        
        table_data = []
        
        for idx, msg_id in enumerate(message_ids, start=1):
            status, msg_data = connection.fetch(msg_id, "(RFC822)")
            if status != "OK":
                print(f"Ошибка при получении письма {msg_id}")
                continue
            
            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)
            
            from_addr = decode_mime_header(msg.get("From", ""))
            to_addr = decode_mime_header(msg.get("To", ""))
            subject = decode_mime_header(msg.get("Subject", "(без темы)"))
            date = parse_email_date(msg.get("Date", ""))
            size = len(raw_email)
            
            attachments = get_attachments_info(msg)
            
            table_data.append([
                start + idx - 1,
                from_addr[:40] + "..." if len(from_addr) > 40 else from_addr,
                to_addr[:40] + "..." if len(to_addr) > 40 else to_addr,
                subject[:50] + "..." if len(subject) > 50 else subject,
                date,
                f"{size:,}",
                len(attachments)
            ])
            
            if attachments:
                print(f"\n--- Письмо #{start + idx - 1} (Тема: {subject[:60]}) ---")
                for i, att in enumerate(attachments, 1):
                    size_mb = att['size'] / (1024 * 1024)
                    size_str = f"{att['size']:,} байт"
                    if size_mb >= 1:
                        size_str = f"{size_mb:.2f} MB ({size_str})"
                    print(f"  Вложение #{i}: {att['filename']} - {size_str}")
        
        print("\n" + "="*120)
        print("СПИСОК ПИСЕМ")
        print("="*120)
        headers = ["№", "От кого", "Кому", "Тема", "Дата", "Размер (байт)", "Вложения"]
        print(tabulate(table_data, headers=headers, tablefmt="grid", stralign="left"))
        
    except Exception as e:
        print(f"Ошибка при обработке писем: {e}")
        import traceback
        traceback.print_exc()
    finally:
        try:
            connection.close()
            connection.logout()
        except:
            pass

if __name__ == "__main__":
    main()