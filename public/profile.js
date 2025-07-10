document.addEventListener('DOMContentLoaded', async () => {
    // Загрузка данных пользователя
    const loadUserData = async () => {
        try {
            const response = await fetch('/api/user');
            if (!response.ok) throw new Error('Ошибка загрузки данных');
            return await response.json();
        } catch (error) {
            console.error('Ошибка:', error);
            alert('Не удалось загрузить данные профиля');
            return null;
        }
    };

    // Инициализация страницы
    const initPage = async () => {
        const user = await loadUserData();
        if (!user) return;

        // Заполнение формы
        document.getElementById('first-name').value = user.firstName || '';
        document.getElementById('last-name').value = user.lastName || '';
        document.getElementById('email-display').textContent = user.email || '';
        document.getElementById('gender').value = user.gender || '';
        document.getElementById('age').value = user.age || '';
        document.getElementById('role').value = user.role || '';
        
        // Аватар
        const avatarPreview = document.getElementById('avatar-preview');
        const headerAvatar = document.getElementById('header-avatar');
        
        if (user.avatarUrl) {
            avatarPreview.src = user.avatarUrl;
            headerAvatar.src = user.avatarUrl;
        } else {
            // Заглушка если аватар отсутствует
            avatarPreview.src = 'https://via.placeholder.com/100';
            headerAvatar.src = 'https://via.placeholder.com/50';
        }

        // Обработчики аватара
        document.getElementById('avatar-url').addEventListener('input', function() {
            if (this.value) {
                avatarPreview.src = this.value;
            }
        });

        document.getElementById('avatar-file').addEventListener('change', function(e) {
            if (this.files && this.files[0]) {
                const reader = new FileReader();
                reader.onload = function(e) {
                    avatarPreview.src = e.target.result;
                }
                reader.readAsDataURL(this.files[0]);
            }
        });
    };

    await initPage();

    // Валидация и отправка формы
    document.getElementById('profile-form').addEventListener('submit', async function(e) {
        e.preventDefault();
        
        // Сброс ошибок
        document.querySelectorAll('.error-message').forEach(el => {
            el.style.display = 'none';
        });

        // Валидация
        let isValid = true;
        const requiredFields = ['first-name', 'last-name', 'gender', 'age', 'role'];
        
        requiredFields.forEach(fieldId => {
            const field = document.getElementById(fieldId);
            if (!field.value) {
                document.getElementById(`${fieldId}-error`).style.display = 'block';
                isValid = false;
            }
        });

        if (!isValid) return;

        // Подготовка данных
        const formData = new FormData();
        formData.append('firstName', this['first-name'].value);
        formData.append('lastName', this['last-name'].value);
        formData.append('gender', this.gender.value);
        formData.append('age', this.age.value);
        formData.append('role', this.role.value);
        
        // Аватар (приоритет у файла)
        const avatarFile = document.getElementById('avatar-file').files[0];
        if (avatarFile) {
            formData.append('avatar', avatarFile);
        } else {
            const avatarUrl = document.getElementById('avatar-url').value;
            if (avatarUrl) formData.append('avatarUrl', avatarUrl);
        }

        // Отправка
        try {
            const response = await fetch('/api/user', {
                method: 'PUT',
                body: formData
            });
            
            if (response.ok) {
                alert('Данные успешно обновлены!');
                // Обновляем аватар в хедере
                const newAvatar = document.getElementById('avatar-preview').src;
                document.getElementById('header-avatar').src = newAvatar;
            } else {
                const errorData = await response.json();
                throw new Error(errorData.message || 'Ошибка сервера');
            }
        } catch (error) {
            console.error('Ошибка:', error);
            alert(`Не удалось обновить данные: ${error.message}`);
        }
    });
});
